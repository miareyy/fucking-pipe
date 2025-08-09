#include <ntifs.h>
#include <fltKernel.h>
#include "pipetap_shared.h"

#define DRIVER_TAG 'TPIP'

PFLT_FILTER gFilter = NULL;
PFLT_PORT gServerPort = NULL;
PFLT_PORT gClientPort = NULL;
FAST_MUTEX gCfgLock;
UNICODE_STRING gFinalComponent = { 0 };
BOOLEAN gEnabled = FALSE;

typedef struct _PT_STREAMHANDLE_CONTEXT { BOOLEAN IsTarget; }PT_STREAMHANDLE_CONTEXT, * PPT_STREAMHANDLE_CONTEXT;

typedef struct _PT_PR_CTX { PT_ORIGIN Opposite; ULONG Pid; ULONG Tid; long long Qpc; ULONG DataLength; UCHAR Data[PT_MAX_PAYLOAD]; }PT_PR_CTX;

static const FLT_CONTEXT_REGISTRATION gCtxReg[] = { {FLT_STREAMHANDLE_CONTEXT,0,NULL,sizeof(PT_STREAMHANDLE_CONTEXT),DRIVER_TAG},{FLT_CONTEXT_END} };

static BOOLEAN PT_NameMatchesFinalComponent(PFLT_CALLBACK_DATA Data) {
    BOOLEAN match = FALSE; PFLT_FILE_NAME_INFORMATION nfo = NULL;
    ExAcquireFastMutex(&gCfgLock);
    BOOLEAN enabled = gEnabled && gFinalComponent.Buffer && gFinalComponent.Length;
    ExReleaseFastMutex(&gCfgLock);
    if (!enabled) return FALSE;
    if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &nfo))) {
        if (NT_SUCCESS(FltParseFileNameInformation(nfo))) {
            ExAcquireFastMutex(&gCfgLock);
            if (gFinalComponent.Buffer && nfo->FinalComponent.Length && RtlCompareUnicodeString(&nfo->FinalComponent, &gFinalComponent, TRUE) == 0) match = TRUE;
            ExReleaseFastMutex(&gCfgLock);
        }
        FltReleaseFileNameInformation(nfo);
    }
    return match;
}

static VOID PT_TagIfTarget(PCFLT_RELATED_OBJECTS FltObjects) {
    PPT_STREAMHANDLE_CONTEXT ctx = NULL;
    if (NT_SUCCESS(FltAllocateContext(FltObjects->Filter, FLT_STREAMHANDLE_CONTEXT, sizeof(PT_STREAMHANDLE_CONTEXT), NonPagedPoolNx, &ctx))) {
        ctx->IsTarget = TRUE;
        FltSetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, FLT_SET_CONTEXT_REPLACE_IF_EXISTS, ctx, NULL);
        FltReleaseContext(ctx);
    }
}

static BOOLEAN PT_IsTarget(PCFLT_RELATED_OBJECTS FltObjects) {
    BOOLEAN isT = FALSE; PPT_STREAMHANDLE_CONTEXT ctx = NULL;
    if (NT_SUCCESS(FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT*)&ctx)) && ctx) {
        isT = ctx->IsTarget ? TRUE : FALSE;
        FltReleaseContext(ctx);
    }
    return isT;
}

static BOOLEAN PT_GetPipeEnd(PCFLT_RELATED_OBJECTS FltObjects, PT_ORIGIN* outEnd) {
    FILE_PIPE_LOCAL_INFORMATION info; RtlZeroMemory(&info, sizeof(info));
    ULONG ret = 0;
    NTSTATUS st = FltQueryInformationFile(FltObjects->Instance, FltObjects->FileObject, &info, sizeof(info), FilePipeLocalInformation, &ret);
    if (!NT_SUCCESS(st)) return FALSE;
    *outEnd = (info.NamedPipeEnd == FILE_PIPE_SERVER_END) ? PT_ORIGIN_SERVER : PT_ORIGIN_CLIENT;
    return TRUE;
}

static PVOID PT_MapWriteBuffer(PFLT_CALLBACK_DATA Data) {
    if (!Data->Iopb->Parameters.Write.MdlAddress) FltLockUserBuffer(Data);
    PVOID p = NULL;
    if (Data->Iopb->Parameters.Write.MdlAddress) p = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Write.MdlAddress, NormalPagePriority);
    else p = Data->Iopb->Parameters.Write.WriteBuffer;
    return p;
}

static NTSTATUS PT_InstanceSetup(PCFLT_RELATED_OBJECTS a, FLT_INSTANCE_SETUP_FLAGS b, DEVICE_TYPE c, FLT_FILESYSTEM_TYPE d) {
    UNREFERENCED_PARAMETER(a); UNREFERENCED_PARAMETER(b); UNREFERENCED_PARAMETER(c); UNREFERENCED_PARAMETER(d);
    return STATUS_SUCCESS;
}

static NTSTATUS PT_MessageNotify(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnOutputBufferLength) {
    UNREFERENCED_PARAMETER(PortCookie); UNREFERENCED_PARAMETER(OutputBuffer); UNREFERENCED_PARAMETER(OutputBufferLength);
    if (ReturnOutputBufferLength)*ReturnOutputBufferLength = 0;
    if (!InputBuffer || InputBufferLength < sizeof(ULONG)) return STATUS_INVALID_PARAMETER;
    const ULONG op = *(const ULONG*)InputBuffer;
    if (op == PT_CMD_SET_PIPE) {
        if (InputBufferLength < sizeof(PT_SET_PIPE_CMD)) return STATUS_INVALID_PARAMETER;
        const PT_SET_PIPE_CMD* cmd = (const PT_SET_PIPE_CMD*)InputBuffer;
        USHORT n = cmd->NameLenBytes;
        if (!n || n > sizeof(cmd->Name) || (n % sizeof(WCHAR)) != 0) return STATUS_INVALID_PARAMETER;
        UNICODE_STRING in; in.Buffer = (PWSTR)cmd->Name; in.Length = in.MaximumLength = n;
        UNICODE_STRING prefix; RtlInitUnicodeString(&prefix, L"\\Device\\NamedPipe\\");
        UNICODE_STRING final = in;
        if (RtlPrefixUnicodeString(&prefix, &in, TRUE)) {
            for (USHORT i = (USHORT)(in.Length / sizeof(WCHAR)); i > 0; --i) {
                if (in.Buffer[i - 1] == L'\\') { final.Buffer = &in.Buffer[i]; final.Length = final.MaximumLength = (USHORT)(in.Length - i * sizeof(WCHAR)); break; }
            }
        }
        ExAcquireFastMutex(&gCfgLock);
        if (gFinalComponent.Buffer) { ExFreePoolWithTag(gFinalComponent.Buffer, DRIVER_TAG); gFinalComponent.Buffer = NULL; gFinalComponent.Length = gFinalComponent.MaximumLength = 0; }
        if (final.Length) {
            gFinalComponent.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, final.Length, DRIVER_TAG);
            if (gFinalComponent.Buffer) { RtlCopyMemory(gFinalComponent.Buffer, final.Buffer, final.Length); gFinalComponent.Length = gFinalComponent.MaximumLength = final.Length; gEnabled = TRUE; }
            else gEnabled = FALSE;
        }
        else gEnabled = FALSE;
        ExReleaseFastMutex(&gCfgLock);
        return gEnabled ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
    }
    else if (op == PT_CMD_CLEAR_PIPE) {
        ExAcquireFastMutex(&gCfgLock);
        if (gFinalComponent.Buffer) { ExFreePoolWithTag(gFinalComponent.Buffer, DRIVER_TAG); gFinalComponent.Buffer = NULL; }
        gFinalComponent.Length = gFinalComponent.MaximumLength = 0;
        gEnabled = FALSE;
        ExReleaseFastMutex(&gCfgLock);
        return STATUS_SUCCESS;
    }
    return STATUS_INVALID_PARAMETER;
}

static NTSTATUS PT_ConnectNotify(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext, PVOID* ConnectionCookie) {
    UNREFERENCED_PARAMETER(ServerPortCookie); UNREFERENCED_PARAMETER(ConnectionContext); UNREFERENCED_PARAMETER(SizeOfContext); UNREFERENCED_PARAMETER(ConnectionCookie);
    if (gClientPort) return STATUS_CONNECTION_ACTIVE;
    gClientPort = ClientPort;
    return STATUS_SUCCESS;
}

static VOID PT_DisconnectNotify(PVOID ConnectionCookie) {
    UNREFERENCED_PARAMETER(ConnectionCookie);
    if (gClientPort) FltCloseClientPort(gFilter, &gClientPort);
}

static FLT_PREOP_CALLBACK_STATUS PT_PreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(CompletionContext);
    if (PT_NameMatchesFinalComponent(Data)) PT_TagIfTarget(FltObjects);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS PT_PostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags) {
    UNREFERENCED_PARAMETER(CompletionContext); UNREFERENCED_PARAMETER(Flags);
    if (NT_SUCCESS(Data->IoStatus.Status) && PT_NameMatchesFinalComponent(Data)) PT_TagIfTarget(FltObjects);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_PREOP_CALLBACK_STATUS PT_PreCreateNamedPipe(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(CompletionContext);
    if (PT_NameMatchesFinalComponent(Data)) PT_TagIfTarget(FltObjects);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS PT_PostCreateNamedPipe(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags) {
    UNREFERENCED_PARAMETER(CompletionContext); UNREFERENCED_PARAMETER(Flags);
    if (NT_SUCCESS(Data->IoStatus.Status) && PT_NameMatchesFinalComponent(Data)) PT_TagIfTarget(FltObjects);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_PREOP_CALLBACK_STATUS PT_PreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(CompletionContext);
    if (!gEnabled || !gClientPort) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    BOOLEAN match = PT_IsTarget(FltObjects);
    if (!match && PT_NameMatchesFinalComponent(Data)) { PT_TagIfTarget(FltObjects); match = TRUE; }
    if (!match) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    PT_ORIGIN end = 0; if (!PT_GetPipeEnd(FltObjects, &end)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    ULONG len = Data->Iopb->Parameters.Write.Length;
    if (!len) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    PVOID src = PT_MapWriteBuffer(Data);
    if (!src) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    PT_EVENT_PAYLOAD ev; RtlZeroMemory(&ev, sizeof(ev));
    ev.Pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    ev.Tid = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    LARGE_INTEGER qpc; KeQueryPerformanceCounter(&qpc);
    ev.TimestampQpc = qpc.QuadPart;
    ev.Origin = end;
    ev.DataLength = (len > PT_MAX_PAYLOAD) ? PT_MAX_PAYLOAD : len;
    RtlCopyMemory(ev.Data, src, ev.DataLength);
    LARGE_INTEGER timeout; timeout.QuadPart = -10 * 1000 * 50;
    if (KeGetCurrentIrql() <= APC_LEVEL) FltSendMessage(gFilter, &gClientPort, &ev, (ULONG)sizeof(PT_EVENT_PAYLOAD), NULL, NULL, &timeout);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS PT_PostReadSafe(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Data); UNREFERENCED_PARAMETER(FltObjects); UNREFERENCED_PARAMETER(Flags);
    PT_PR_CTX* cx = (PT_PR_CTX*)CompletionContext;
    if (cx && gClientPort) {
        PT_EVENT_PAYLOAD ev; RtlZeroMemory(&ev, sizeof(ev));
        ev.Pid = cx->Pid; ev.Tid = cx->Tid; ev.TimestampQpc = cx->Qpc;
        ev.Origin = cx->Opposite; ev.DataLength = cx->DataLength;
        RtlCopyMemory(ev.Data, cx->Data, ev.DataLength);
        LARGE_INTEGER to; to.QuadPart = -10 * 1000 * 50;
        FltSendMessage(gFilter, &gClientPort, &ev, (ULONG)sizeof(ev), NULL, NULL, &to);
        ExFreePoolWithTag(cx, DRIVER_TAG);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_PREOP_CALLBACK_STATUS PT_PreRead(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(CompletionContext);
    if (!gEnabled || !gClientPort) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    BOOLEAN match = PT_IsTarget(FltObjects);
    if (!match && PT_NameMatchesFinalComponent(Data)) { PT_TagIfTarget(FltObjects); match = TRUE; }
    if (!match) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!Data->Iopb->Parameters.Read.Length) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!Data->Iopb->Parameters.Read.MdlAddress) FltLockUserBuffer(Data);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS PT_PostRead(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags) {
    UNREFERENCED_PARAMETER(CompletionContext);
    if (!NT_SUCCESS(Data->IoStatus.Status)) return FLT_POSTOP_FINISHED_PROCESSING;
    if (!gEnabled || !gClientPort) return FLT_POSTOP_FINISHED_PROCESSING;
    BOOLEAN match = PT_IsTarget(FltObjects);
    if (!match && PT_NameMatchesFinalComponent(Data)) { PT_TagIfTarget(FltObjects); match = TRUE; }
    if (!match) return FLT_POSTOP_FINISHED_PROCESSING;
    PT_ORIGIN end = 0; if (!PT_GetPipeEnd(FltObjects, &end)) return FLT_POSTOP_FINISHED_PROCESSING;
    ULONG_PTR got = Data->IoStatus.Information; if (!got) return FLT_POSTOP_FINISHED_PROCESSING;
    PVOID sys = NULL; PMDL mdl = Data->Iopb->Parameters.Read.MdlAddress;
    if (mdl) sys = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority); else sys = Data->Iopb->Parameters.Read.ReadBuffer;
    if (!sys) return FLT_POSTOP_FINISHED_PROCESSING;
    PT_PR_CTX* cx = (PT_PR_CTX*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PT_PR_CTX), DRIVER_TAG);
    if (!cx) return FLT_POSTOP_FINISHED_PROCESSING;
    RtlZeroMemory(cx, sizeof(*cx));
    cx->Pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    cx->Tid = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    LARGE_INTEGER qpc; KeQueryPerformanceCounter(&qpc); cx->Qpc = qpc.QuadPart;
    cx->Opposite = (end == PT_ORIGIN_SERVER) ? PT_ORIGIN_CLIENT : PT_ORIGIN_SERVER;
    cx->DataLength = (ULONG)((got > PT_MAX_PAYLOAD) ? PT_MAX_PAYLOAD : got);
    RtlCopyMemory(cx->Data, sys, cx->DataLength);
    FLT_POSTOP_CALLBACK_STATUS s;
    if (FltDoCompletionProcessingWhenSafe(Data, FltObjects, cx, Flags, PT_PostReadSafe, &s)) return s;
    ExFreePoolWithTag(cx, DRIVER_TAG);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static VOID PT_CleanupClose(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects) {
    UNREFERENCED_PARAMETER(Data); UNREFERENCED_PARAMETER(FltObjects);
}

static NTSTATUS PT_Unload(FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    if (gServerPort) { FltCloseCommunicationPort(gServerPort); gServerPort = NULL; }
    if (gFilter) { FltUnregisterFilter(gFilter); gFilter = NULL; }
    ExAcquireFastMutex(&gCfgLock);
    if (gFinalComponent.Buffer) { ExFreePoolWithTag(gFinalComponent.Buffer, DRIVER_TAG); gFinalComponent.Buffer = NULL; }
    gFinalComponent.Length = gFinalComponent.MaximumLength = 0;
    gEnabled = FALSE;
    ExReleaseFastMutex(&gCfgLock);
    return STATUS_SUCCESS;
}

static const FLT_OPERATION_REGISTRATION gOps[] = {
    {IRP_MJ_CREATE,0,PT_PreCreate,PT_PostCreate},
    {IRP_MJ_CREATE_NAMED_PIPE,0,PT_PreCreateNamedPipe,PT_PostCreateNamedPipe},
    {IRP_MJ_READ,0,PT_PreRead,PT_PostRead},
    {IRP_MJ_WRITE,0,PT_PreWrite,NULL},
    {IRP_MJ_CLEANUP,0,NULL,(PFLT_POST_OPERATION_CALLBACK)PT_CleanupClose},
    {IRP_MJ_CLOSE,0,NULL,(PFLT_POST_OPERATION_CALLBACK)PT_CleanupClose},
    {IRP_MJ_OPERATION_END}
};

static const FLT_REGISTRATION gReg = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    FLTFL_REGISTRATION_SUPPORT_NPFS_MSFS,
    gCtxReg,
    gOps,
    PT_Unload,
    PT_InstanceSetup,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status = FltRegisterFilter(DriverObject, &gReg, &gFilter);
    if (!NT_SUCCESS(status)) return status;
    ExInitializeFastMutex(&gCfgLock);
    PSECURITY_DESCRIPTOR sd = NULL;
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) { FltUnregisterFilter(gFilter); return status; }
    UNICODE_STRING portName; RtlInitUnicodeString(&portName, PT_PORT_NAME);
    OBJECT_ATTRIBUTES oa; InitializeObjectAttributes(&oa, &portName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);
    status = FltCreateCommunicationPort(gFilter, &gServerPort, &oa, NULL, PT_ConnectNotify, PT_DisconnectNotify, PT_MessageNotify, 1);
    FltFreeSecurityDescriptor(sd);
    if (!NT_SUCCESS(status)) { FltUnregisterFilter(gFilter); return status; }
    return FltStartFiltering(gFilter);
}
