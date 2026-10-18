// Original bounded static graph traversal. Raw instructions and paths stay private.
//@category BullyResearch
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;

public class BoundedReferenceGraph extends GhidraScript {
    private void saveValueIndex(Path out,HighFunction function) throws Exception {
        List<PcodeOpAST> operations=new ArrayList<>();function.getPcodeOps().forEachRemaining(operations::add);
        IdentityHashMap<PcodeOp,Integer> opIds=new IdentityHashMap<>();
        IdentityHashMap<Varnode,Integer> nodeIds=new IdentityHashMap<>();
        for(int i=0;i<operations.size();i++)opIds.put(operations.get(i),i);
        List<Object> encodedOps=new ArrayList<>();
        for(int i=0;i<operations.size();i++) {
            PcodeOpAST op=operations.get(i);List<Integer> inputs=new ArrayList<>();
            for(int j=0;j<op.getNumInputs();j++) {
                Varnode node=op.getInput(j);if(!nodeIds.containsKey(node))nodeIds.put(node,nodeIds.size());
                inputs.add(nodeIds.get(node));
            }
            Varnode output=op.getOutput();
            if(output!=null && !nodeIds.containsKey(output))nodeIds.put(output,nodeIds.size());
            Map<String,Object> encoded=new LinkedHashMap<>();encoded.put("id",i);encoded.put("opcode",op.getMnemonic());
            encoded.put("site",op.getSeqnum().getTarget().toString());encoded.put("inputs",inputs);
            encoded.put("output",output==null?null:nodeIds.get(output));encodedOps.add(encoded);
        }
        List<Map<String,Object>> nodes=new ArrayList<>();
        for(var item:nodeIds.entrySet()) {
            Varnode node=item.getKey();Map<String,Object> encoded=new LinkedHashMap<>();
            encoded.put("id",item.getValue());encoded.put("size",node.getSize());
            encoded.put("space",node.getAddress().getAddressSpace().getName());
            encoded.put("offset",Long.toUnsignedString(node.getOffset(),16));encoded.put("constant",node.isConstant());
            encoded.put("input",node.isInput());encoded.put("definition",opIds.get(node.getDef()));nodes.add(encoded);
        }
        nodes.sort(Comparator.comparingInt(x->(Integer)x.get("id")));
        save(out.resolve("private-value-index.json"),Map.of("nodes",nodes,"operations",encodedOps,
            "scope","one decompiled entry hypothesis; raw evidence remains private"));
    }
    private Map<String,Object> origin(Varnode root) {
        Set<Varnode> seen=Collections.newSetFromMap(new IdentityHashMap<>());
        ArrayDeque<Varnode> queue=new ArrayDeque<>();queue.add(root);
        int dynamicLoads=0,constantLoads=0,inputs=0,callResults=0;
        while(!queue.isEmpty() && seen.size()<256) {
            Varnode value=queue.removeFirst();if(!seen.add(value) || value.isConstant())continue;
            PcodeOp def=value.getDef();if(def==null) {inputs++;continue;}
            if(def.getOpcode()==PcodeOp.LOAD) {
                if(def.getInput(1).isConstant())constantLoads++;else dynamicLoads++;
                continue;
            }
            if(def.getOpcode()==PcodeOp.CALL || def.getOpcode()==PcodeOp.CALLIND) {callResults++;continue;}
            for(int i=0;i<def.getNumInputs();i++)queue.add(def.getInput(i));
        }
        return Map.of("root_is_constant",root.isConstant(),"visited_values",seen.size(),
            "dynamic_address_load_dependencies",dynamicLoads,"constant_address_load_dependencies",constantLoads,
            "unbound_input_dependencies",inputs,"call_return_dependencies",callResults,"budget_hit",!queue.isEmpty());
    }
    private void save(Path p,Object value) throws Exception {
        Files.writeString(p,new GsonBuilder().setPrettyPrinting().create().toJson(value)+"\n",StandardOpenOption.CREATE_NEW);
    }
    public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=3 || !args[1].equalsIgnoreCase(currentProgram.getExecutableSHA256()))
            throw new IllegalStateException("target identity/arguments mismatch");
        Path out=Paths.get(args[0]);
        JsonObject request=JsonParser.parseString(Files.readString(Paths.get(args[2]))).getAsJsonObject();
        Address entry=toAddr(request.get("entry_va").getAsLong());
        AddressSet allowed=new AddressSet();
        String section=request.get("section").getAsString();
        var block=currentProgram.getMemory().getBlock(entry);
        if(block==null || !block.getName().equals(section) || block.getSize()>400000)
            throw new IllegalStateException("unexpected entry block");
        allowed.add(block.getStart(),block.getEnd());
        var existing=currentProgram.getListing().getCodeUnitContaining(entry);
        if(request.has("parent_call_site") && existing!=null) {
            save(out.resolve("root-loader-state.json"),Map.of("unit_class",existing.getClass().getSimpleName(),
                "unit_length",existing.getLength(),"root_offset_in_unit",entry.subtract(existing.getMinAddress())));
            // Reset only imported analysis units in this bounded block; original bytes are never written.
            clearListing(block.getStart(),block.getEnd());
        }
        Map<Address,JsonObject> wanted=new HashMap<>();
        for(JsonElement element:request.getAsJsonArray("references")) {
            JsonObject ref=element.getAsJsonObject();
            wanted.put(toAddr(ref.get("source_va").getAsLong()),ref);
        }
        if(wanted.size()>16) throw new IllegalArgumentException("reference cap");
        ArrayDeque<Address> queue=new ArrayDeque<>();queue.add(entry);
        Map<Address,Address> parent=new HashMap<>();parent.put(entry,null);
        Set<Address> visited=new HashSet<>();
        List<Object> edges=new ArrayList<>(), terminals=new ArrayList<>(), matched=new ArrayList<>();
        List<Object> indirect=new ArrayList<>();
        Set<Address> jumpSites=new HashSet<>();
        AddressSet body=new AddressSet();
        StringBuilder listing=new StringBuilder();
        int bytes=0,calls=0,computedCalls=0,computedJumps=0,returns=0,undecoded=0,outside=0;
        boolean budget=false;int computedSitesWithAddressReferences=0,directCallsToNext=0;
        while(!queue.isEmpty()) {
            monitor.checkCancelled();
            if(visited.size()>=16384 || bytes>=65536) { budget=true;break; }
            Address at=queue.removeFirst();
            if(!visited.add(at)) continue;
            if(!allowed.contains(at)) { outside++;continue; }
            if(currentProgram.getListing().getInstructionAt(at)==null)
                new DisassembleCommand(at,new AddressSet(at,at),false).applyTo(currentProgram,monitor);
            Instruction ins=currentProgram.getListing().getInstructionAt(at);
            if(ins==null || !allowed.contains(ins.getMaxAddress())) { undecoded++;continue; }
            if(bytes+ins.getLength()>65536) { budget=true;break; }
            bytes+=ins.getLength();body.add(ins.getMinAddress(),ins.getMaxAddress());
            listing.append(at).append(' ').append(ins).append('\n');
            var flow=ins.getFlowType();
            if(flow.isComputed()) {
                List<Object> refs=new ArrayList<>();
                for(var ref:ins.getReferencesFrom()) {
                    Address target=ref.getToAddress();
                    var targetBlock=currentProgram.getMemory().getBlock(target);
                    refs.add(Map.of("to",target.toString(),"type",ref.getReferenceType().toString(),
                        "section",targetBlock==null?"external-or-unmapped":targetBlock.getName()));
                }
                if(!refs.isEmpty())computedSitesWithAddressReferences++;
                indirect.add(Map.of("site",at.toString(),"call",flow.isCall(),"references",refs));
            }
            List<Address> next=new ArrayList<>();
            if(flow.isCall()) {
                calls++;if(flow.isComputed())computedCalls++;
                for(Address dest:ins.getFlows()) {
                    if(dest.equals(ins.getFallThrough()))directCallsToNext++;
                    edges.add(Map.of("from",at.toString(),"to",dest.toString(),"kind","call"));
                    JsonObject expected=wanted.get(at);
                    if(expected!=null && dest.getOffset()==expected.get("target_va").getAsLong()) {
                        List<String> path=new ArrayList<>();Address cursor=at;
                        while(cursor!=null) { path.add(cursor.toString());cursor=parent.get(cursor); }
                        Collections.reverse(path);
                        matched.add(Map.of("candidate_id",expected.get("candidate_id").getAsInt(),
                            "source_va",at.toString(),"target_va",dest.toString(),"path",path));
                    }
                }
            } else {
                if(flow.isComputed()) { computedJumps++;jumpSites.add(at);terminals.add(Map.of("address",at.toString(),"kind","computed-flow")); }
                next.addAll(Arrays.asList(ins.getFlows()));
            }
            if(ins.getMnemonicString().equalsIgnoreCase("RET"))returns++;
            Address fall=ins.getFallThrough();if(fall!=null)next.add(fall);
            if(next.isEmpty() && !flow.isCall())terminals.add(Map.of("address",at.toString(),"kind",flow.toString()));
            for(Address dest:next) {
                edges.add(Map.of("from",at.toString(),"to",dest.toString(),"kind",dest.equals(fall)?"fallthrough":"branch"));
                if(!parent.containsKey(dest)) { parent.put(dest,at);queue.add(dest); }
            }
        }
        Files.writeString(out.resolve("reachable.asm"),listing.toString(),StandardOpenOption.CREATE_NEW);
        save(out.resolve("private-edges.json"),edges);save(out.resolve("private-terminals.json"),terminals);
        save(out.resolve("private-matched-paths.json"),matched);
        save(out.resolve("private-indirect-references.json"),indirect);
        Map<String,Object> summary=new LinkedHashMap<>();
        summary.put("target_sha256",args[1]);summary.put("graph_completed",!budget);summary.put("budget_exhausted",budget);
        summary.put("auto_analysis",false);summary.put("seeded_at_executable_entry",!request.has("parent_call_site"));
        summary.put("root_kind",request.has("parent_call_site")?"validated-direct-callee":"executable-entry");
        summary.put("section",section);summary.put("reference_leads",wanted.size());summary.put("matched_call_paths",matched.size());
        summary.put("visited_instruction_addresses",visited.size());summary.put("decoded_bytes",bytes);
        summary.put("decoded_byte_budget",65536);summary.put("instruction_budget",16384);
        summary.put("calls",calls);summary.put("computed_calls",computedCalls);summary.put("computed_jumps",computedJumps);
        summary.put("computed_sites_with_address_references",computedSitesWithAddressReferences);
        summary.put("direct_calls_to_next_instruction",directCallsToNext);
        summary.put("returns",returns);summary.put("undecoded_destinations",undecoded);summary.put("destinations_outside_section",outside);
        summary.put("body_range_count",body.getNumAddressRanges());
        summary.put("closed_returning_body",!budget && computedJumps==0 && returns>0 && undecoded==0 && outside==0);
        summary.put("queued_at_stop",queue.size());summary.put("max_heap_bytes",Runtime.getRuntime().maxMemory());
        summary.put("reported_processors",Runtime.getRuntime().availableProcessors());
        summary.put("conditional_feasibility_evaluated",false);summary.put("call_returns_assumed",true);
        summary.put("game_functions_recovered",0);summary.put("target_executed",false);
        if(request.has("inspect_indirect_dataflow") && request.get("inspect_indirect_dataflow").getAsBoolean() && !budget && body.contains(entry)) {
            Function function=currentProgram.getFunctionManager().getFunctionAt(entry);
            if(function==null) function=currentProgram.getFunctionManager().createFunction("entry_probe",entry,body,SourceType.ANALYSIS);
            DecompInterface decompiler=new DecompInterface();
            try {
                if(!decompiler.openProgram(currentProgram))throw new IllegalStateException("decompiler unavailable");
                DecompileResults result=decompiler.decompileFunction(function,10,monitor);
                summary.put("entry_decompile_completed",result.decompileCompleted());
                Files.writeString(out.resolve("entry-decompile-diagnostics.txt"),result.getErrorMessage(),StandardOpenOption.CREATE_NEW);
                if(result.decompileCompleted()) {
                    Files.writeString(out.resolve("entry-pseudocode.c"),result.getDecompiledFunction().getC(),StandardOpenOption.CREATE_NEW);
                    saveValueIndex(out,result.getHighFunction());
                    List<Object> dependencies=new ArrayList<>();
                    Iterator<PcodeOpAST> operations=result.getHighFunction().getPcodeOps();
                    while(operations.hasNext()) {
                        PcodeOpAST op=operations.next();
                        if(!jumpSites.contains(op.getSeqnum().getTarget()) ||
                           (op.getOpcode()!=PcodeOp.BRANCHIND && op.getOpcode()!=PcodeOp.CALLIND))continue;
                        Map<String,Object> detail=new LinkedHashMap<>();
                        detail.put("site",op.getSeqnum().getTarget().toString());
                        detail.put("flow_operation",op.getMnemonic());
                        Varnode root=op.getInput(0);detail.put("target_is_constant",root.isConstant());
                        if(root.isConstant()) {
                            var targetBlock=currentProgram.getMemory().getBlock(toAddr(root.getOffset()));
                            detail.put("constant_target_section",targetBlock==null?"unmapped":targetBlock.getName());
                        }
                        Set<Varnode> seen=Collections.newSetFromMap(new IdentityHashMap<>());
                        ArrayDeque<Varnode> pending=new ArrayDeque<>();pending.add(root);
                        Map<String,Integer> kinds=new TreeMap<>();int loads=0,dynamicLoads=0,inputLeaves=0,callLeaves=0;
                        List<Object> callTargets=new ArrayList<>();
                        while(!pending.isEmpty() && seen.size()<256) {
                            Varnode var=pending.removeFirst();if(!seen.add(var) || var.isConstant())continue;
                            PcodeOp def=var.getDef();
                            if(def==null) { inputLeaves++;continue; }
                            kinds.merge(def.getMnemonic(),1,Integer::sum);
                            if(def.getOpcode()==PcodeOp.LOAD) {
                                loads++;if(!def.getInput(1).isConstant())dynamicLoads++;continue;
                            }
                            if(def.getOpcode()==PcodeOp.CALL || def.getOpcode()==PcodeOp.CALLIND) {
                                callLeaves++;
                                callTargets.add(Map.of("call_site",def.getSeqnum().getTarget().toString(),
                                    "same_site_as_terminal",def.getSeqnum().getTarget().equals(op.getSeqnum().getTarget()),
                                    "kind",def.getMnemonic(),"target_origin",origin(def.getInput(0))));
                                continue;
                            }
                            for(int i=0;i<def.getNumInputs();i++)pending.add(def.getInput(i));
                        }
                        detail.put("visited_values",seen.size());detail.put("traversal_budget_hit",!pending.isEmpty());
                        detail.put("load_value_dependencies",loads);detail.put("dynamic_address_load_dependencies",dynamicLoads);
                        detail.put("unbound_input_dependencies",inputLeaves);detail.put("call_return_dependencies",callLeaves);
                        detail.put("call_target_dependencies",callTargets);
                        detail.put("operation_counts",kinds);dependencies.add(detail);
                    }
                    save(out.resolve("private-indirect-dataflow.json"),dependencies);
                    summary.put("computed_jump_dataflow_records",dependencies.size());
                    // Aggregate only. The private graph is an analyzer observation, not a contract.
                    summary.put("computed_jump_target_constant",dependencies.size()==1 &&
                        Boolean.TRUE.equals(((Map<?,?>)dependencies.get(0)).get("target_is_constant")));
                }
            } finally {decompiler.dispose();}
        }
        save(out.resolve("summary.json"),summary);
    }
}
