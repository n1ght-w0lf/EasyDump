#include "plugin.h"

// Global vars to hold allocated mem address and size
static duint mem_addr;
static duint mem_size;

// Helper function to log fail messages
static bool fail(char* message) {
    _plugin_logprintf("[" PLUGIN_NAME "] %s\n", message);

    return false;
}

// Helper function to get parent path
static char* getParentPath(char* path) {
    char* pos = strrchr(path, '\\');
    if (pos != NULL) {
        *pos = '\0';
    }
    return path;
}

// VirtualAlloc BP callback
static void cbVirtualAlloc() {
    mem_addr = Script::Register::GetCAX();
    // auto x = GetFunctionParameter(DbgGetProcessHandle(), UE_FUNCTION_STDCALL_RET, 2, UE_PARAMETER_DWORD);
    mem_size = DbgEval("arg.get(1)");

    _plugin_logprintf("[" PLUGIN_NAME "] VirtualAlloc addr: %x\n", mem_addr);
    _plugin_logprintf("[" PLUGIN_NAME "] VirtualAlloc size: %x\n", mem_size);
}

// VirtualProtect BP callback
static void cbVirtualProtect() {
    auto header = Script::Memory::ReadWord(mem_addr);
    // Check for MZ header
    if (header == 0x5a4d) {
        _plugin_logprintf("[" PLUGIN_NAME "] Found a PE file at addr: %x\n", mem_addr);

        // Build dumping path
        char path[MAX_PATH];
        Script::Module::GetMainModulePath(path);
        sprintf(path, "%s\\memdump_%X_%zx_%zx.bin", getParentPath(path), DbgGetProcessId(), mem_addr, mem_size);

        // Dump payload to disk
        if (DumpMemory(DbgGetProcessHandle(), (LPVOID)mem_addr, mem_size, path))
            _plugin_logprintf("[" PLUGIN_NAME "] Dumped payload at %s\n", path);
        else
            fail("Failed to dump the payload");
    }
}

static bool cbEasyDump(int argc, char* argv[]) {
    // Delete All BPs
    DbgCmdExec("bpc");

    // Set BP on VirtualAlloc ret
    if (!SetAPIBreakPoint("kernelbase.dll", "VirtualAlloc", UE_BREAKPOINT, UE_APIEND, cbVirtualAlloc))
        fail("Failed to set a Breakpoint on VirtualAlloc");

    // Set BP on VirtualProtect start
    if (!SetAPIBreakPoint("kernelbase.dll", "VirtualProtect", UE_BREAKPOINT, UE_APISTART, cbVirtualProtect))
        fail("Failed to set a Breakpoint on VirtualProtect");

    _plugin_logprint("[" PLUGIN_NAME "] Starting the program...\n");
    DbgCmdExec("run");

    return true;
}

// Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    _plugin_logputs("[" PLUGIN_NAME "] Loaded successfully!");

    if (!_plugin_registercommand(pluginHandle, "EasyDump", cbEasyDump, true))
        return fail("Failed to register command");

    return true; // Return false to cancel loading the plugin.
}

// Deinitialize your plugin data here.
void pluginStop()
{
    _plugin_unregistercommand(pluginHandle, "EasyDump");
}

// Do GUI/Menu related things here.
void pluginSetup()
{
}
