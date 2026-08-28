/*
 * Deterministic IPALift analysis configuration.
 *
 * Ghidra's Objective-C Message Analyzer can install order-dependent call
 * overrides for dynamic objc_msgSend sites. IPALift keeps those sites explicit
 * and associates selectors separately from recovered evidence.
 */
//@category IPALift

import ghidra.app.script.GhidraScript;

public class IPALiftConfigure extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("No current program is available to the IPALift configuration script");
        }
        setAnalysisOption(currentProgram, "Objective-C Message Analyzer", "false");
        println("IPALift: disabled Objective-C Message Analyzer for deterministic explicit dispatch");
    }
}
