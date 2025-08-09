#pragma once
#define PT_PORT_NAME L"\\PipeTapPort"
#define PT_MAX_PAYLOAD 4096

typedef enum _PT_CMD_OP { PT_CMD_SET_PIPE = 1, PT_CMD_CLEAR_PIPE = 2 } PT_CMD_OP;

typedef struct _PT_SET_PIPE_CMD { unsigned long Op; unsigned short NameLenBytes; wchar_t Name[260]; } PT_SET_PIPE_CMD;

typedef struct _PT_CLEAR_PIPE_CMD { unsigned long Op; } PT_CLEAR_PIPE_CMD;

typedef enum _PT_ORIGIN { PT_ORIGIN_SERVER = 1, PT_ORIGIN_CLIENT = 2 } PT_ORIGIN;

typedef struct _PT_EVENT_PAYLOAD { unsigned long Pid; unsigned long Tid; long long TimestampQpc; unsigned long Origin; unsigned long DataLength; unsigned char Data[PT_MAX_PAYLOAD]; } PT_EVENT_PAYLOAD;
