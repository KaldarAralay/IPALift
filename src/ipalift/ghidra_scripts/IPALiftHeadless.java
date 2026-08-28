/*
 * IPALift headless evidence importer and exporter.
 *
 * This script runs only as an analyzeHeadless postScript. It applies recovered
 * names before invoking the decompiler, then emits raw deterministic records
 * for IPALift's Python normalization layer.
 */
//@category IPALift

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

import com.google.gson.*;

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.util.DefinedStringIterator;

public class IPALiftHeadless extends GhidraScript {

    private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
    private JsonObject evidence;
    private Path outputRoot;
    private Path codeRoot;
    private int functionTimeout;
    private int appliedMethodGroups = 0;
    private int appliedMethodRecords = 0;
    private int appliedSymbols = 0;
    private int appliedSections = 0;
    private int appliedFrameworks = 0;
    private final JsonArray missingMethodGroups = new JsonArray();

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException(
                "IPALiftHeadless.java requires <evidence.json> <raw-output-directory> <function-timeout-seconds>");
        }
        if (currentProgram == null) {
            throw new IllegalStateException("No current program is available to the IPALift script");
        }
        evidence = JsonParser.parseReader(Files.newBufferedReader(Path.of(args[0]), StandardCharsets.UTF_8))
            .getAsJsonObject();
        outputRoot = Path.of(args[1]);
        codeRoot = outputRoot.resolve("code");
        functionTimeout = Integer.parseInt(args[2]);
        Files.createDirectories(outputRoot);
        Files.createDirectories(codeRoot);

        println("IPALift: applying recovered evidence before decompilation");
        applyEvidence();
        println("IPALift: exporting strings, functions, cross-references, blocks, and calls");
        exportStrings();
        exportFunctionsAndCalls();
        println("IPALift: attempting decompilation of every internal non-thunk function");
        exportDecompilation();
        writeManifest();
        println("IPALift: completed raw headless export");
    }

    private Address evidenceAddress(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String cleaned = value.toLowerCase(Locale.ROOT).startsWith("0x") ? value.substring(2) : value;
        try {
            long offset = Long.parseUnsignedLong(cleaned, 16);
            return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        }
        catch (RuntimeException error) {
            return null;
        }
    }

    private String address(Address value) {
        if (value == null) {
            return null;
        }
        if (!value.getAddressSpace().equals(currentProgram.getAddressFactory().getDefaultAddressSpace())) {
            return value.getAddressSpace().getName() + ":" + value.toString();
        }
        int width = currentProgram.getDefaultPointerSize() == 8 ? 16 : 8;
        return String.format(Locale.ROOT, "0x%0" + width + "x", value.getOffset());
    }

    private void addNullable(JsonObject object, String property, String value) {
        if (value == null) {
            object.add(property, JsonNull.INSTANCE);
        }
        else {
            object.addProperty(property, value);
        }
    }

    private String safeName(String value) {
        String cleaned = value == null ? "anonymous" : value.replaceAll("[^A-Za-z0-9_$]", "_");
        cleaned = cleaned.replaceAll("_+", "_").replaceAll("^_+|_+$", "");
        if (cleaned.isEmpty()) {
            cleaned = "anonymous";
        }
        if (Character.isDigit(cleaned.charAt(0))) {
            cleaned = "n_" + cleaned;
        }
        return cleaned.length() > 180 ? cleaned.substring(0, 180) : cleaned;
    }

    private String functionId(Function function) {
        if (function == null) {
            return null;
        }
        if (function.isExternal()) {
            return "external:" + function.getName(true) + "@" + function.getEntryPoint().toString();
        }
        return address(function.getEntryPoint());
    }

    private Function functionAtOrContaining(Address target) {
        if (target == null) {
            return null;
        }
        FunctionManager manager = currentProgram.getFunctionManager();
        Function exact = manager.getFunctionAt(target);
        return exact != null ? exact : manager.getFunctionContaining(target);
    }

    private void applyEvidence() throws Exception {
        applyFrameworks();
        applySections();
        applySymbols();
        applyObjectiveCMethods();
    }

    private void applyFrameworks() throws Exception {
        ExternalManager manager = currentProgram.getExternalManager();
        Set<String> existing = new HashSet<>();
        for (String name : manager.getExternalLibraryNames()) {
            existing.add(name.toLowerCase(Locale.ROOT));
        }
        for (JsonElement element : evidence.getAsJsonArray("frameworks")) {
            JsonObject framework = element.getAsJsonObject();
            String name = framework.get("name").getAsString();
            String lowered = name.toLowerCase(Locale.ROOT);
            boolean found = existing.stream().anyMatch(value -> value.equals(lowered) || value.endsWith("/" + lowered));
            if (!found) {
                try {
                    manager.addExternalLibraryName(name, SourceType.IMPORTED);
                    existing.add(lowered);
                }
                catch (Exception ignored) {
                    // Existing loader-created paths can reject a simplified duplicate name.
                }
            }
            appliedFrameworks++;
        }
    }

    private void applySections() throws Exception {
        SymbolTable table = currentProgram.getSymbolTable();
        for (JsonElement element : evidence.getAsJsonArray("sections")) {
            JsonObject section = element.getAsJsonObject();
            if (section.get("address").isJsonNull()) {
                continue;
            }
            Address target = evidenceAddress(section.get("address").getAsString());
            if (target == null || !currentProgram.getMemory().contains(target)) {
                continue;
            }
            String segment = section.get("segment").isJsonNull() ? "segment" : section.get("segment").getAsString();
            String name = section.get("name").isJsonNull() ? "section" : section.get("name").getAsString();
            String label = safeName("section_" + segment + "_" + name);
            boolean present = false;
            for (Symbol symbol : table.getSymbols(target)) {
                if (symbol.getName().equals(label)) {
                    present = true;
                    break;
                }
            }
            if (!present) {
                try {
                    table.createLabel(target, label, SourceType.IMPORTED);
                }
                catch (Exception ignored) {
                    // A loader label may already own this exact namespace/name combination.
                }
            }
            appliedSections++;
        }
    }

    private void applySymbols() throws Exception {
        SymbolTable table = currentProgram.getSymbolTable();
        for (JsonElement element : evidence.getAsJsonArray("symbols")) {
            JsonObject record = element.getAsJsonObject();
            Address target = evidenceAddress(record.get("address").getAsString());
            if (target == null || !currentProgram.getMemory().contains(target)) {
                continue;
            }
            String exactName = record.get("name").getAsString();
            boolean present = false;
            for (Symbol symbol : table.getSymbols(target)) {
                if (symbol.getName().equals(exactName) || symbol.getName().equals(safeName(exactName))) {
                    present = true;
                    break;
                }
            }
            if (!present) {
                try {
                    table.createLabel(target, safeName(exactName), SourceType.IMPORTED);
                }
                catch (Exception ignored) {
                    // Invalid or duplicate loader labels remain available through raw Mach-O evidence.
                }
            }
            appliedSymbols++;
        }
    }

    private void applyObjectiveCMethods() throws Exception {
        FunctionManager manager = currentProgram.getFunctionManager();
        SymbolTable symbols = currentProgram.getSymbolTable();
        for (JsonElement element : evidence.getAsJsonArray("methods")) {
            monitor.checkCancelled();
            JsonObject group = element.getAsJsonObject();
            String addressText = group.get("address").getAsString();
            Address target = evidenceAddress(addressText);
            Function function = target == null ? null : manager.getFunctionAt(target);
            if (function == null && target != null && currentProgram.getMemory().contains(target)) {
                try {
                    if (currentProgram.getListing().getInstructionAt(target) == null) {
                        disassemble(target);
                    }
                    function = createFunction(target, group.get("internal_name").getAsString());
                }
                catch (Exception ignored) {
                    function = manager.getFunctionAt(target);
                }
            }
            if (function == null || !function.getEntryPoint().equals(target)) {
                JsonObject missing = new JsonObject();
                missing.addProperty("address", addressText);
                missing.add("exact_names", group.getAsJsonArray("exact_names").deepCopy());
                Function containing = target == null ? null : manager.getFunctionContaining(target);
                addNullable(missing, "containing_function", functionId(containing));
                missing.addProperty("reason", target == null ? "invalid address" : "no exact function entry");
                missingMethodGroups.add(missing);
                continue;
            }
            String namespaceName = group.get("namespace").getAsString();
            Namespace namespace = symbols.getNamespace(namespaceName, currentProgram.getGlobalNamespace());
            if (namespace == null) {
                namespace = symbols.createNameSpace(
                    currentProgram.getGlobalNamespace(), namespaceName, SourceType.USER_DEFINED);
            }
            try {
                function.setParentNamespace(namespace);
                function.setName(group.get("internal_name").getAsString(), SourceType.USER_DEFINED);
            }
            catch (Exception ignored) {
                // The exact evidence remains in the comment and exported objective_c_methods list.
            }
            List<String> exactNames = new ArrayList<>();
            for (JsonElement exact : group.getAsJsonArray("exact_names")) {
                exactNames.add(exact.getAsString());
            }
            Collections.sort(exactNames);
            function.setComment("IPALift exact Objective-C methods:\n" + String.join("\n", exactNames));
            appliedMethodGroups++;
            appliedMethodRecords += group.getAsJsonArray("records").size();
        }
    }

    private List<Function> allFunctions() {
        List<Function> result = new ArrayList<>();
        FunctionManager manager = currentProgram.getFunctionManager();
        FunctionIterator internal = manager.getFunctions(true);
        while (internal.hasNext()) {
            result.add(internal.next());
        }
        FunctionIterator external = manager.getExternalFunctions();
        while (external.hasNext()) {
            result.add(external.next());
        }
        result.sort(Comparator.comparing(this::functionId));
        return result;
    }

    private void writeLine(BufferedWriter writer, JsonObject value) throws IOException {
        writer.write(gson.toJson(value));
        writer.newLine();
    }

    private JsonObject referenceRecord(Reference reference) {
        JsonObject item = new JsonObject();
        item.addProperty("from_address", address(reference.getFromAddress()));
        addNullable(item, "to_address", address(reference.getToAddress()));
        item.addProperty("reference_type", reference.getReferenceType().toString());
        item.addProperty("operand_index", reference.getOperandIndex());
        item.addProperty("primary", reference.isPrimary());
        item.addProperty("call", reference.getReferenceType().isCall());
        item.addProperty("data", reference.getReferenceType().isData());
        Symbol targetSymbol = currentProgram.getSymbolTable().getPrimarySymbol(reference.getToAddress());
        addNullable(item, "target_symbol", targetSymbol == null ? null : targetSymbol.getName(true));
        Function targetFunction = functionAtOrContaining(reference.getToAddress());
        addNullable(item, "target_function_id", functionId(targetFunction));
        return item;
    }

    private JsonArray basicBlocks(Function function, SimpleBlockModel model) throws Exception {
        JsonArray blocks = new JsonArray();
        if (function.isExternal()) {
            return blocks;
        }
        CodeBlockIterator iterator = model.getCodeBlocksContaining(function.getBody(), monitor);
        while (iterator.hasNext()) {
            CodeBlock block = iterator.next();
            JsonObject item = new JsonObject();
            item.addProperty("start", address(block.getMinAddress()));
            item.addProperty("end", address(block.getMaxAddress()));
            item.addProperty("size", block.getNumAddresses());
            int instructionCount = 0;
            InstructionIterator instructions = currentProgram.getListing().getInstructions(block, true);
            while (instructions.hasNext()) {
                instructions.next();
                instructionCount++;
            }
            item.addProperty("instruction_count", instructionCount);
            JsonArray destinations = new JsonArray();
            CodeBlockReferenceIterator destinationIterator = block.getDestinations(monitor);
            while (destinationIterator.hasNext()) {
                CodeBlockReference destination = destinationIterator.next();
                JsonObject edge = new JsonObject();
                addNullable(edge, "target", address(destination.getDestinationAddress()));
                edge.addProperty("flow_type", destination.getFlowType().toString());
                destinations.add(edge);
            }
            item.add("destinations", destinations);
            blocks.add(item);
        }
        return blocks;
    }

    private JsonObject callRecord(Function caller, Instruction instruction, Reference reference) {
        JsonObject edge = new JsonObject();
        edge.addProperty("caller_id", functionId(caller));
        edge.addProperty("call_site", address(instruction.getAddress()));
        if (reference == null) {
            edge.add("target_address", JsonNull.INSTANCE);
            edge.add("target_function_id", JsonNull.INSTANCE);
            edge.add("target_name", JsonNull.INSTANCE);
            edge.add("thunk_target_name", JsonNull.INSTANCE);
            edge.addProperty("reference_type", instruction.getFlowType().toString());
            edge.addProperty("indirect", true);
            return edge;
        }
        Address target = reference.getToAddress();
        Function targetFunction = functionAtOrContaining(target);
        Symbol targetSymbol = currentProgram.getSymbolTable().getPrimarySymbol(target);
        addNullable(edge, "target_address", address(target));
        addNullable(edge, "target_function_id", functionId(targetFunction));
        String targetName = targetFunction != null ? targetFunction.getName(true) :
            (targetSymbol == null ? null : targetSymbol.getName(true));
        addNullable(edge, "target_name", targetName);
        Function thunkTarget = targetFunction != null && targetFunction.isThunk() ?
            targetFunction.getThunkedFunction(false) : null;
        addNullable(edge, "thunk_target_name", thunkTarget == null ? null : thunkTarget.getName(true));
        edge.addProperty("reference_type", reference.getReferenceType().toString());
        edge.addProperty("indirect", false);
        return edge;
    }

    private void exportFunctionsAndCalls() throws Exception {
        Path functionsPath = outputRoot.resolve("functions.jsonl");
        Path callsPath = outputRoot.resolve("calls.jsonl");
        Listing listing = currentProgram.getListing();
        SimpleBlockModel blockModel = new SimpleBlockModel(currentProgram);
        try (BufferedWriter functionWriter = Files.newBufferedWriter(functionsPath, StandardCharsets.UTF_8);
             BufferedWriter callWriter = Files.newBufferedWriter(callsPath, StandardCharsets.UTF_8)) {
            int processed = 0;
            for (Function function : allFunctions()) {
                monitor.checkCancelled();
                JsonObject record = new JsonObject();
                record.addProperty("id", functionId(function));
                if (function.isExternal()) {
                    record.add("address", JsonNull.INSTANCE);
                }
                else {
                    record.addProperty("address", address(function.getEntryPoint()));
                }
                record.addProperty("address_space", function.getEntryPoint().getAddressSpace().getName());
                record.addProperty("name", function.getName());
                record.addProperty("full_name", function.getName(true));
                record.addProperty("namespace", function.getParentNamespace().getName(true));
                record.addProperty("signature", function.getPrototypeString(false, false));
                record.addProperty("source_type", function.getSymbol().getSource().toString());
                record.addProperty("external", function.isExternal());
                record.addProperty("thunk", function.isThunk());
                Function thunkTarget = function.isThunk() ? function.getThunkedFunction(false) : null;
                addNullable(record, "thunk_target_id", functionId(thunkTarget));
                record.addProperty("entrypoint", function.getSymbol().isExternalEntryPoint());
                if (function.isExternal()) {
                    record.add("body_start", JsonNull.INSTANCE);
                    record.add("body_end", JsonNull.INSTANCE);
                    record.addProperty("size", 0);
                }
                else {
                    record.addProperty("body_start", address(function.getBody().getMinAddress()));
                    record.addProperty("body_end", address(function.getBody().getMaxAddress()));
                    record.addProperty("size", function.getBody().getNumAddresses());
                }
                record.add("basic_blocks", basicBlocks(function, blockModel));
                JsonArray references = new JsonArray();
                if (!function.isExternal()) {
                    InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
                    while (instructions.hasNext()) {
                        Instruction instruction = instructions.next();
                        boolean hasCallReference = false;
                        for (Reference reference : instruction.getReferencesFrom()) {
                            references.add(referenceRecord(reference));
                            if (reference.getReferenceType().isCall()) {
                                hasCallReference = true;
                                writeLine(callWriter, callRecord(function, instruction, reference));
                            }
                        }
                        if (instruction.getFlowType().isCall() && !hasCallReference) {
                            writeLine(callWriter, callRecord(function, instruction, null));
                        }
                    }
                }
                record.add("cross_references", references);
                writeLine(functionWriter, record);
                processed++;
                if (processed % 500 == 0) {
                    println("IPALift: exported " + processed + " functions");
                }
            }
        }
    }

    private void exportStrings() throws Exception {
        Path stringsPath = outputRoot.resolve("strings.jsonl");
        ReferenceManager references = currentProgram.getReferenceManager();
        try (BufferedWriter writer = Files.newBufferedWriter(stringsPath, StandardCharsets.UTF_8)) {
            for (Data data : DefinedStringIterator.forProgram(currentProgram, null)) {
                monitor.checkCancelled();
                StringDataInstance instance = StringDataInstance.getStringDataInstance(data);
                String value = instance.getStringValue();
                if (value == null) {
                    continue;
                }
                JsonObject record = new JsonObject();
                record.addProperty("address", address(data.getAddress()));
                record.addProperty("value", value);
                record.addProperty("length", data.getLength());
                record.addProperty("data_type", data.getDataType().getName());
                JsonArray incoming = new JsonArray();
                ReferenceIterator iterator = references.getReferencesTo(data.getAddress());
                while (iterator.hasNext()) {
                    Reference reference = iterator.next();
                    JsonObject item = new JsonObject();
                    item.addProperty("from_address", address(reference.getFromAddress()));
                    item.addProperty("reference_type", reference.getReferenceType().toString());
                    Function function = currentProgram.getFunctionManager().getFunctionContaining(reference.getFromAddress());
                    addNullable(item, "from_function_id", functionId(function));
                    incoming.add(item);
                }
                record.add("references", incoming);
                writeLine(writer, record);
            }
        }
    }

    private void exportDecompilation() throws Exception {
        Path decompilationPath = outputRoot.resolve("decompilation.jsonl");
        DecompileOptions options = new DecompileOptions();
        DecompInterface decompiler = new DecompInterface();
        decompiler.setOptions(options);
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Cannot initialize Ghidra decompiler: " + decompiler.getLastMessage());
        }
        try (BufferedWriter writer = Files.newBufferedWriter(decompilationPath, StandardCharsets.UTF_8)) {
            int attempted = 0;
            for (Function function : allFunctions()) {
                monitor.checkCancelled();
                if (function.isExternal() || function.isThunk()) {
                    continue;
                }
                JsonObject record = new JsonObject();
                record.addProperty("function_id", functionId(function));
                record.addProperty("address", address(function.getEntryPoint()));
                String status = "failure";
                String message = null;
                String outputFile = null;
                try {
                    DecompileResults results = decompiler.decompileFunction(function, functionTimeout, monitor);
                    message = results.getErrorMessage();
                    if (results.decompileCompleted() && results.getDecompiledFunction() != null) {
                        String code = results.getDecompiledFunction().getC();
                        outputFile = address(function.getEntryPoint()).substring(2) + ".c";
                        Files.writeString(
                            codeRoot.resolve(outputFile),
                            code.replace("\r\n", "\n").replace("\r", "\n"),
                            StandardCharsets.UTF_8,
                            StandardOpenOption.CREATE,
                            StandardOpenOption.TRUNCATE_EXISTING);
                        status = "success";
                    }
                    else if (message != null && message.toLowerCase(Locale.ROOT).contains("timeout")) {
                        status = "timeout";
                    }
                }
                catch (Exception error) {
                    message = error.getClass().getSimpleName() + ": " + error.getMessage();
                    if (message.toLowerCase(Locale.ROOT).contains("timeout")) {
                        status = "timeout";
                    }
                }
                record.addProperty("status", status);
                addNullable(record, "message", message == null || message.isBlank() ? null : message);
                addNullable(record, "raw_output_file", outputFile);
                writeLine(writer, record);
                attempted++;
                if (attempted % 100 == 0) {
                    println("IPALift: attempted decompilation of " + attempted + " functions");
                }
            }
        }
        finally {
            decompiler.dispose();
        }
    }

    private void writeManifest() throws Exception {
        JsonObject manifest = new JsonObject();
        manifest.addProperty("completed", true);
        manifest.addProperty("ghidra_version", Application.getApplicationVersion());
        manifest.addProperty("language_id", currentProgram.getLanguageID().toString());
        manifest.addProperty(
            "compiler_spec_id", currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
        manifest.addProperty("executable_format", currentProgram.getExecutableFormat());
        manifest.addProperty("image_base", address(currentProgram.getImageBase()));
        manifest.addProperty("applied_method_group_count", appliedMethodGroups);
        manifest.addProperty("applied_method_record_count", appliedMethodRecords);
        manifest.addProperty("missing_method_group_count", missingMethodGroups.size());
        manifest.add("missing_method_groups", missingMethodGroups);
        manifest.addProperty("applied_symbol_count", appliedSymbols);
        manifest.addProperty("applied_section_count", appliedSections);
        manifest.addProperty("applied_framework_count", appliedFrameworks);
        manifest.addProperty("objective_c_message_analyzer_enabled", false);
        manifest.addProperty("max_cpu", 1);
        JsonArray blocks = new JsonArray();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            JsonObject item = new JsonObject();
            item.addProperty("name", block.getName());
            item.addProperty("start", address(block.getStart()));
            item.addProperty("end", address(block.getEnd()));
            item.addProperty("size", block.getSize());
            item.addProperty("read", block.isRead());
            item.addProperty("write", block.isWrite());
            item.addProperty("execute", block.isExecute());
            blocks.add(item);
        }
        manifest.add("memory_blocks", blocks);
        JsonArray libraries = new JsonArray();
        String[] libraryNames = currentProgram.getExternalManager().getExternalLibraryNames();
        Arrays.sort(libraryNames);
        for (String library : libraryNames) {
            libraries.add(library);
        }
        manifest.add("external_libraries", libraries);
        Files.writeString(
            outputRoot.resolve("manifest.json"),
            new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create().toJson(manifest) + "\n",
            StandardCharsets.UTF_8,
            StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING);
    }
}
