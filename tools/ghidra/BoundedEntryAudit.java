// Original bounded static audit. No game execution or source recovery claim.
// Run with -noanalysis. Raw listing stays in the caller's private directory.
//@category BullyResearch
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class BoundedEntryAudit extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("private output directory and SHA-256 required");
        if (!args[1].equalsIgnoreCase(currentProgram.getExecutableSHA256()))
            throw new IllegalStateException("imported target hash mismatch");
        Path out = Paths.get(args[0]);
        Address start = toAddr(0x020f32edL);
        Address end = start.add(255);
        AddressSet bounds = new AddressSet(start, end);
        if (!currentProgram.getMemory().contains(bounds))
            throw new IllegalStateException("window not mapped");
        // Ghidra restricts instruction starts, not complete instruction spans.
        // x86 instructions are at most 15 bytes; reserve the final 14 start bytes.
        AddressSet starts = new AddressSet(start, end.subtract(14));
        DisassembleCommand command = new DisassembleCommand(start, starts, true);
        boolean applied = command.applyTo(currentProgram, monitor);
        StringBuilder listing = new StringBuilder();
        int count = 0, bytes = 0, externalFlows = 0, terminals = 0, calls = 0;
        for (Instruction ins : currentProgram.getListing().getInstructions(bounds, true)) {
            monitor.checkCancelled();
            if (!bounds.contains(ins.getMaxAddress()))
                throw new IllegalStateException("instruction extends beyond window");
            count++; bytes += ins.getLength();
            listing.append(ins.getAddress()).append(' ').append(ins.toString()).append('\n');
            if (ins.getFlowType().isTerminal()) terminals++;
            if (ins.getFlowType().isCall()) calls++;
            for (Address flow : ins.getFlows()) if (!bounds.contains(flow)) externalFlows++;
            Address fall = ins.getFallThrough();
            if (fall != null && !bounds.contains(fall)) externalFlows++;
        }
        Files.writeString(out.resolve("reachable-listing.asm"), listing.toString(),
            StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
        String json = "{\n" +
            "  \"schema_version\": 1,\n" +
            "  \"target_sha256\": \"" + args[1] + "\",\n" +
            "  \"window_start_va\": \"0x020f32ed\",\n" +
            "  \"window_bytes\": 256,\n" +
            "  \"instruction_start_budget_bytes\": 242,\n" +
            "  \"reserved_tail_bytes\": 14,\n" +
            "  \"auto_analysis\": false,\n" +
            "  \"disassembly_applied\": " + applied + ",\n" +
            "  \"reachable_instruction_count\": " + count + ",\n" +
            "  \"decoded_bytes\": " + bytes + ",\n" +
            "  \"flow_edges_outside_window\": " + externalFlows + ",\n" +
            "  \"terminal_instructions\": " + terminals + ",\n" +
            "  \"call_instructions\": " + calls + ",\n" +
            "  \"analysis_function_records\": " + currentProgram.getFunctionManager().getFunctionCount() + ",\n" +
            "  \"language_id\": \"" + currentProgram.getLanguageID() + "\",\n" +
            "  \"loader_compiler_spec\": \"" + currentProgram.getCompilerSpec().getCompilerSpecID() + "\",\n" +
            "  \"observed_max_heap_bytes\": " + Runtime.getRuntime().maxMemory() + ",\n" +
            "  \"jvm_reported_processors\": " + Runtime.getRuntime().availableProcessors() + ",\n" +
            "  \"game_functions_recovered\": 0,\n" +
            "  \"complete_function_boundary_established\": false,\n" +
            "  \"original_game_executed\": false\n" + "}\n";
        Files.writeString(out.resolve("summary.json"), json, StandardCharsets.UTF_8,
            StandardOpenOption.CREATE_NEW);
    }
}
