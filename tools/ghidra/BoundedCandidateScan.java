// Original static candidate filter. All detailed outputs must remain private.
//@category BullyResearch
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;

public class BoundedCandidateScan extends GhidraScript {
    private void save(Path p, Object value) throws Exception {
        Files.writeString(p, new GsonBuilder().setPrettyPrinting().create().toJson(value)+"\n",
            StandardOpenOption.CREATE_NEW);
    }
    public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=3 || !args[1].equalsIgnoreCase(currentProgram.getExecutableSHA256()))
            throw new IllegalStateException("argument/target identity mismatch");
        Path out=Paths.get(args[0]);
        List<String> seeds=Files.readAllLines(Paths.get(args[2]));
        if(seeds.isEmpty() || seeds.size()>6) throw new IllegalArgumentException("1..6 seeds required");
        List<Object> probes=new ArrayList<>();
        int closed=0, decompiled=0;
        for(int index=0;index<seeds.size();index++) {
            monitor.checkCancelled();
            Address start=toAddr(Long.parseUnsignedLong(seeds.get(index).trim(),16));
            Address end=start.add(255);
            AddressSet bounds=new AddressSet(start,end);
            Map<String,Object> row=new LinkedHashMap<>();
            row.put("id",index+1); row.put("entry_va",start.toString());
            row.put("entry_rva",start.subtract(currentProgram.getImageBase()));
            row.put("window_bytes",256); row.put("reserved_tail_bytes",14);
            probes.add(row);
            if(!currentProgram.getMemory().contains(bounds)) { row.put("rejection","unmapped window"); continue; }
            String section=currentProgram.getMemory().getBlock(start).getName(); row.put("section",section);
            new DisassembleCommand(start,new AddressSet(start,end.subtract(14)),true).applyTo(currentProgram,monitor);
            ArrayDeque<Address> queue=new ArrayDeque<>(); queue.add(start);
            Set<Address> visited=new HashSet<>(); AddressSet body=new AddressSet();
            TreeSet<Integer> pops=new TreeSet<>();
            List<String> failures=new ArrayList<>(); int calls=0,returns=0;
            StringBuilder listing=new StringBuilder();
            while(!queue.isEmpty() && visited.size()<128) {
                Address address=queue.removeFirst();
                if(!visited.add(address)) continue;
                if(!bounds.contains(address)) { failures.add("outgoing branch or fallthrough"); continue; }
                Instruction ins=currentProgram.getListing().getInstructionAt(address);
                if(ins==null) { failures.add("undecoded destination"); continue; }
                if(!bounds.contains(ins.getMaxAddress())) { failures.add("instruction outside budget"); continue; }
                body.add(ins.getMinAddress(),ins.getMaxAddress());
                listing.append(ins.getAddress()).append(' ').append(ins).append('\n');
                String mnemonic=ins.getMnemonicString().toUpperCase(Locale.ROOT);
                if(mnemonic.equals("RET")) {
                    returns++;
                    pops.add(ins.getNumOperands()==0?0:(int)ins.getScalar(0).getUnsignedValue());
                    continue;
                }
                if(ins.getFlowType().isCall()) calls++;
                else {
                    if(ins.getFlowType().isComputed()) failures.add("unresolved computed flow");
                    for(Address flow:ins.getFlows()) queue.add(flow);
                }
                Address fall=ins.getFallThrough();
                if(fall!=null) queue.add(fall);
                else if(ins.getFlows().length==0) failures.add("non-return terminal");
            }
            if(!queue.isEmpty()) failures.add("instruction count budget");
            if(returns==0) failures.add("no return");
            row.put("visited_instruction_addresses",visited.size());row.put("body_bytes",body.getNumAddresses());
            row.put("calls",calls);row.put("returns",returns);row.put("return_pop_bytes",pops);
            row.put("boundary_failures",new TreeSet<>(failures));
            boolean eligible=failures.isEmpty() && calls==0 && !body.isEmpty();
            row.put("closed_leaf_candidate",eligible);
            Files.writeString(out.resolve("candidate-"+(index+1)+".asm"),listing.toString(),StandardOpenOption.CREATE_NEW);
            if(!eligible) continue;
            closed++;
            row.put("body_min",body.getMinAddress().toString());row.put("body_max",body.getMaxAddress().toString());
            row.put("body_range_count",body.getNumAddressRanges());
            Function function=currentProgram.getFunctionManager().createFunction(
                "candidate_"+(index+1),start,body,SourceType.ANALYSIS);
            DecompInterface decompiler=new DecompInterface();
            try {
                if(!decompiler.openProgram(currentProgram)) throw new IllegalStateException("decompiler open failed");
                DecompileResults result=decompiler.decompileFunction(function,10,monitor);
                row.put("decompile_completed",result.decompileCompleted());
                Files.writeString(out.resolve("candidate-"+(index+1)+"-diagnostic.txt"),result.getErrorMessage(),StandardOpenOption.CREATE_NEW);
                if(result.decompileCompleted()) {
                    Files.writeString(out.resolve("candidate-"+(index+1)+".c"),result.getDecompiledFunction().getC(),StandardOpenOption.CREATE_NEW);
                    decompiled++;
                }
            } finally { decompiler.dispose(); }
        }
        save(out.resolve("private-candidates.json"),probes);
        Map<String,Object> summary=new LinkedHashMap<>();
        summary.put("target_sha256",args[1]); summary.put("seed_count",seeds.size());
        summary.put("scan_completed",true);
        summary.put("closed_leaf_candidates",closed); summary.put("decompiled_candidates",decompiled);
        summary.put("window_bytes_per_seed",256); summary.put("instruction_start_budget_bytes",242);
        summary.put("max_instructions_per_seed",128);summary.put("decompile_timeout_seconds_per_candidate",10);
        summary.put("auto_analysis",false);summary.put("max_heap_bytes",Runtime.getRuntime().maxMemory());
        summary.put("reported_processors",Runtime.getRuntime().availableProcessors());
        summary.put("function_records_are_created_hypotheses",true);
        summary.put("game_functions_recovered",0);summary.put("original_oracle_tests",0);
        save(out.resolve("summary.json"),summary);
    }
}
