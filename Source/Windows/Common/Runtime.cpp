#define _FILE_DEFINED
struct FILE;
#define _SECIMP
#define _CRTIMP
#include <map>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cerrno>
#include <atomic>
#include <io.h>
#include <unistd.h>
#include <ctype.h>
#include <wchar.h>
#include <windef.h>
#include <winternl.h>
#include <heapapi.h>
#include <fcntl.h>
#include <wine/debug.h>
#include "LibC.h"

#define DLLEXPORT_FUNC(Ret, Name, Args, Body) \
  Ret Name Args Body \
  Ret (*__MINGW_IMP_SYMBOL(Name)) Args = Name;

struct FILE {
    HANDLE Handle{INVALID_HANDLE_VALUE};
    bool Append{false};
};

namespace {
unsigned short CTypeData[256];
char *Env;

void InitEnv() {
    RtlAcquirePebLock();
    auto ProcessParams = reinterpret_cast<RTL_USER_PROCESS_PARAMETERS64 *>(NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters);
    wchar_t *EnvW = reinterpret_cast<wchar_t *>(ProcessParams->Environment);
    DWORD SizeW = 2;
    // The PEB environment is terminated by two null wchars.
    for (wchar_t *It = EnvW; *It != 0 || *(It + 1) != 0; It++, SizeW++);

    DWORD Size;
    RtlUnicodeToMultiByteSize(&Size, EnvW, SizeW);
    Env = reinterpret_cast<char *>(RtlAllocateHeap(GetProcessHeap(), 0, Size));
    RtlUnicodeToMultiByteN(Env, Size, nullptr, EnvW, SizeW); 
    RtlReleasePebLock();
}

int ErrnoReturn(int Value) {
  errno = Value;
  return -1;
}
}

namespace FEX::Windows {
    void InitLibCProcess() {
	InitEnv();
    }
}
extern "C" {
#define DBG() __wine_dbg_output( __func__ ); __wine_dbg_output( "\n" )

#define JEMALLOC_NOTHROW __attribute__((nothrow))
JEMALLOC_NOTHROW extern void* je_malloc(size_t size);
JEMALLOC_NOTHROW extern void* je_calloc(size_t n, size_t size);
JEMALLOC_NOTHROW extern void* je_memalign(size_t align, size_t s);
JEMALLOC_NOTHROW extern void* je_valloc(size_t size);
JEMALLOC_NOTHROW extern int je_posix_memalign(void** r, size_t a, size_t s);
JEMALLOC_NOTHROW extern void* je_realloc(void* ptr, size_t size);
JEMALLOC_NOTHROW extern void je_free(void* ptr);
JEMALLOC_NOTHROW extern size_t je_malloc_usable_size(void* ptr);
JEMALLOC_NOTHROW extern void* je_aligned_alloc(size_t a, size_t s);
#undef JEMALLOC_NOTHROW
}

void *calloc(size_t NumOfElements,size_t SizeOfElements) { DBG(); return je_calloc(NumOfElements, SizeOfElements); }
void free(void *Memory) { DBG(); je_free(Memory); }
void *malloc(size_t Size) { DBG(); return je_malloc(Size); }
void *realloc(void *Memory,size_t NewSize) { DBG(); return je_realloc(Memory, NewSize);}
DLLEXPORT_FUNC(void *, _aligned_malloc, (size_t Size, size_t Alignment), { DBG(); return je_aligned_alloc(Alignment, Size); })
DLLEXPORT_FUNC(void, _aligned_free, (void *Memory), { DBG(); je_free(Memory); })


// io.h File Operatons
namespace {
    std::mutex FileTableLock;
    std::vector<FILE *> OpenFileTable;
    DWORD OpenFlagToAccess(int OpenFlag) {
	if (OpenFlag & _O_RDONLY) return GENERIC_READ;
	if (OpenFlag & _O_WRONLY) return GENERIC_WRITE;
	if (OpenFlag & _O_RDWR) return GENERIC_READ | GENERIC_WRITE;
        return 0;
    }

    DWORD OpenFlagToCreation(int OpenFlag) {
	if ((OpenFlag & (_O_TRUNC | _O_CREAT)) == (_O_TRUNC | _O_CREAT)) return CREATE_ALWAYS;
	if ((OpenFlag & (_O_EXCL | _O_CREAT)) == (_O_EXCL | _O_CREAT)) return CREATE_NEW;
	if (OpenFlag & _O_TRUNC) return TRUNCATE_EXISTING;
	if (OpenFlag & _O_CREAT) return OPEN_ALWAYS;
	return OPEN_EXISTING;
    }

    int AllocateFile(FILE *File) {
        std::scoped_lock Lock{FileTableLock};
	auto It = std::find(OpenFileTable.begin(), OpenFileTable.end(), nullptr);
	if (It == OpenFileTable.end()) {
	    It = OpenFileTable.emplace_back(File);
	}
	size_t Idx = std::distance(OpenFileTable.begin(), It);
	if (Idx >= std::numeric_limit<int>::max()) std::terminate();
	return static_cast<int>(Idx);
    }

    FILE *GetFile(int FileHandle)  {
        std::scoped_lock Lock{FileTableLock};
	return OpenFileTable[FileHandle];
    }
}

DLLEXPORT_FUNC(int, _wopen, (const wchar_t *Filename, int OpenFlag, ...), { DBG();
    DWORD Attrs = 0;
    if (OpenFlag & _O_CREAT) {
        va_list VA;
        int PermMode;
        va_start(VA, OpenFlag);
        PermMode = va_arg(VA, int);
        va_end(VA);
	if (!(PermMode & _S_IWRITE)) Attrs = FILE_ATTRIBUTE_READONLY;
    }
    HANDLE Handle = CreateFileW(Filename, OpenFlagToAccess(OpenFlag), 0, nullptr, OpenFlagToCreation(OpenFlag), Attrs, nullptr);
    if (Handle != INVALID_HANDLE_VALUE)
	return AllocateFile(new FILE(Handle, OpenFlag & _O_APPEND));

    if (GetLastError() == ERROR_FILE_EXISTS) return ErrnoReturn(EEXIST);
    if (GetLastError() == ERROR_FILE_NOT_FOUND) return ErrnoReturn(ENOENT);
    if (GetLastError() == ERROR_ACCESS_DENIED) return ErrnoReturn(EACCES);
    return ErrnoReturn(ENOENT);
})

DLLEXPORT_FUNC(int, _open, (const char *Filename, int OpenFlag, ...), { DBG(); 
    UNICODE_STRING FilenameW;
    if (!RtlCreateUnicodeStringFromAsciiz(&FilenameW, Filename))
	return ErrnoReturn(EINVAL);
    int ret = 0;
    if (OpenFlag & _O_CREAT) {
        va_list VA;
        int PermMode;
        va_start(VA, OpenFlag);
        PermMode = va_arg(VA, int);
        va_end(VA);
    ret = _wopen(FilenameW.Buffer, OpenFlag, PermMode);
    } else {
    ret = _wopen(FilenameW.Buffer, OpenFlag);
    }
    RtlFreeUnicodeString(&FilenameW);
    return ret;
})
DLLEXPORT_FUNC(int, open, (const char *Filename, int OpenFlag, ...), { DBG();
    if (OpenFlag & _O_CREAT) {
    va_list VA;
    int PermMode;
    va_start(VA, OpenFlag);
    PermMode = va_arg(VA, int);
    va_end(VA);
    return _open(Filename, OpenFlag, PermMode);
    }
    return _open(Filename, OpenFlag);
})

DLLEXPORT_FUNC(int, _close, (int _FileHandle), { DBG(); })
int close(int FileHandle) { return _close(FileHandle); }

int64_t _lseeki64(int FileHandle, int64_t Offset, int Origin) { DBG(); }

int64_t _telli64(int FileHandle) { DBG(); }

DLLEXPORT_FUNC(int, _read, (int _FileHandle,void *_DstBuf,unsigned int _MaxCharCount), {})
int read(int FileHandle,void *DstBuf,unsigned int MaxCharCount) { DBG(); return _read(FileHandle, DstBuf, MaxCharCount); }

DLLEXPORT_FUNC(int, _write, (int _Filehandle,const void *_Buf,unsigned int _MaxCharCount), { DBG(); })
int write(int FileHandle,const void *Buf,unsigned int MaxCharCount) { return _write(FileHandle, Buf, MaxCharCount); }

DLLEXPORT_FUNC(int, _isatty, (int _FileHandle), { DBG(); })
DLLEXPORT_FUNC(intptr_t, _get_osfhandle, (int _FileHandle), { DBG(); })


// stdio.h File Operations
namespace {
    template<auto StrchrFunc, typename TChar>
    int ModeToOpenFlag(const TChar *Mode) {
        int OpenFlag = 0;
        if (StrchrFunc(Mode, 'a')) {
            OpenFlag |= _O_RDWR | _O_CREAT | _O_APPEND;
        } else if (auto Ptr = StrchrFunc(Mode, 'r')) {
	    if (Ptr[1] == '+')
                OpenFlag |= _O_RDWR;
	    else
                OpenFlag |= _O_RDONLY;
	} else {
            OpenFlag |= _O_RDWR | _O_CREAT | _O_TRUNC;
	}
        if (StrchrFunc(Mode, 'x')) OpenFlag |= _O_EXCL;
	return OpenFlag;
    }
}
DLLEXPORT_FUNC(FILE *, _wfopen, (const wchar_t * __restrict__ Filename,const wchar_t *__restrict__  Mode), { DBG();
    int OpenFlag = ModeToOpenFlag<wcschr>(Mode)
    int Ret = _wopen(Filename, OpenFlag, _S_IWRITE | _S_IREAD);
    if (Ret == -1) return -1;
    return GetFile(Ret);
})
FILE *fopen(const char * __restrict__ _Filename,const char * __restrict__ _Mode) { DBG(); 
    int OpenFlag = ModeToOpenFlag<strchr>(Mode)
    int Ret = _open(Filename, OpenFlag, _S_IWRITE | _S_IREAD);
    if (Ret == -1) return -1;
    return GetFile(Ret);
}

FILE *fdopen(int _FileHandle,const char *_Mode) { DBG(); }
int fclose(FILE *_File) { DBG(); }

int fseeko64(FILE* _File, _off64_t _Offset, int _Origin) { DBG(); }
int fseeko(FILE* File, _off_t Offset, int Origin) { return fseeko64(File, Offset, Origin); }
int fseek(FILE *File,long Offset,int Origin) { return fseeko64(File, Offset, Origin); }

_off64_t ftello64(FILE * _File) { DBG(); }
_off_t ftello(FILE *File) { return (_off_t)ftello64(File); }
long ftell(FILE *File) { return (long)ftello64(File); }

size_t fread(void * __restrict__ _DstBuf,size_t _ElementSize,size_t _Count,FILE * __restrict__ _File) { DBG(); }
size_t fwrite(const void * __restrict__ _Str,size_t _Size,size_t _Count,FILE * __restrict__ _File) { DBG(); }

void setbuf(FILE * __restrict__ _File,char * __restrict__ _Buffer) { DBG(); }
int fflush(FILE *_File) { DBG(); 
}
int __mingw_vfprintf (FILE * __restrict__ , const char * __restrict__ , va_list) { DBG(); }

int ungetc(int _Ch,FILE *_File) { DBG(); }
wint_t fgetwc(FILE *_File) { DBG(); }
wint_t fputwc(wchar_t _Ch,FILE *_File) { DBG(); }
int fputc(int _Ch,FILE *_File) { DBG(); }
int getc(FILE *_File) { DBG(); }
wint_t ungetwc(wint_t _Ch,FILE *_File) { DBG(); }
DLLEXPORT_FUNC(FILE *, __acrt_iob_func, (unsigned index), { DBG(); return nullptr; })
DLLEXPORT_FUNC(int, _fileno, (FILE *_File), { DBG(); })

int atexit(void (*)(void)) { DBG(); return 0; }

#pragma push_macro("abort")
#undef abort
void abort(void) { DBG(); }
#pragma pop_macro("abort")

int access(const char *Path, int AccessMode) { DBG();
    UNICODE_STRING PathW;
    if (!RtlCreateUnicodeStringFromAsciiz(&PathW, Path))
	return ErrnoReturn(EINVAL);

    UNICODE_STRING NTPath;
    bool Success = RtlDosPathNameToNtPathName_U(PathW.Buffer, &NTPath, nullptr, nullptr);
    RtlFreeUnicodeString(&PathW);
    if (!Success)
	return ErrnoReturn(EINVAL);

    OBJECT_ATTRIBUTES ObjAttributes;
    InitializeObjectAttributes(&ObjAttributes, &NTPath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    FILE_BASIC_INFORMATION Info;
    Success = !NtQueryAttributesFile(&ObjAttributes, &Info);
    RtlFreeUnicodeString(&NTPath);

    if (!Success)
	return ErrnoReturn(ENOENT);

    return !((AccessMode & W_OK) && (Info.FileAttributes & FILE_ATTRIBUTE_READONLY));
}

int rename(const char *_OldFilename,const char *_NewFilename) { DBG(); }
float __mingw_strtof (const char * __restrict__, char ** __restrict__) { DBG(); }
double __mingw_strtod (const char * __restrict__, char ** __restrict__) { DBG(); }

int getpid(void) { DBG(); }
long long wcstoll(const wchar_t * __restrict__ nptr,wchar_t ** __restrict__ endptr, int base) { DBG(); }
unsigned long long wcstoull(const wchar_t * __restrict__ nptr,wchar_t ** __restrict__ endptr, int base) { DBG(); }
char *setlocale(int _Category,const char *_Locale) { DBG(); return "C"; }
unsigned long long  strtoull(const char * __restrict__, char ** __restrict__, int) { DBG(); }
long long  strtoll(const char * __restrict__, char ** __restrict, int) { DBG(); }
long double strtold(const char * __restrict__ , char ** __restrict__ ) { DBG(); }
double __mingw_wcstod(const wchar_t * __restrict__ _Str,wchar_t ** __restrict__ _EndPtr) { DBG(); }
long double wcstold(const wchar_t * __restrict__, wchar_t ** __restrict__) { DBG(); }
float __mingw_wcstof(const wchar_t * __restrict__ nptr, wchar_t ** __restrict__ endptr) { DBG(); }
int __mingw_vsnwprintf (wchar_t * __restrict__ , size_t, const wchar_t * __restrict__ , va_list) { DBG(); }

int __mingw_vsprintf (char * __restrict__ , const char * __restrict__ , va_list) { DBG(); }
int __mingw_vsscanf (const char * __restrict__ _Str,const char * __restrict__ Format,va_list argp) { DBG(); }
int _configthreadlocale(int _Flag) { DBG(); return 0; }

size_t mbsrtowcs(wchar_t * __restrict__ _Dest,const char ** __restrict__ _PSrc,size_t _Count,mbstate_t * __restrict__ _State) __MINGW_ATTRIB_DEPRECATED_SEC_WARN { DBG(); }
size_t mbrtowc(wchar_t * __restrict__ _DstCh,const char * __restrict__ _SrcCh,size_t _SizeInBytes,mbstate_t * __restrict__ _State) { DBG(); }
size_t strftime(char * __restrict__ _Buf,size_t _SizeInBytes,const char * __restrict__ _Format,const struct tm * __restrict__ _Tm)  { DBG(); }
long double tanl(long double) { DBG(); }
long double sinl(long double) { DBG(); }
double exp2(double) { DBG(); }
double fmod(double _X,double _Y) { DBG(); }
char *getenv(const char *VarName) { 
    DBG();
    size_t VarNameLen = strlen(VarName);
    char *It = Env;
    char *Ret = nullptr;

    while (*It) {
      char *Eq = strchr(It, '=');
      if (Eq && Eq - It == VarNameLen && !strncmp(It, VarName, VarNameLen)) {
        Ret = Eq + 1;
	break;
      }

      It += strlen(It) + 1;
    }

    return Ret;
}

int __mingw_vsnprintf(char * __restrict__ _DstBuf,size_t _MaxCount,const char * __restrict__ _Format, va_list _ArgList) { DBG(); }
void exit(int _Code) { DBG(); }
size_t mbrlen(const char * __restrict__ _Ch,size_t _SizeInBytes,mbstate_t * __restrict__ _State) { DBG(); }
size_t wcrtomb(char * __restrict__ _Dest,wchar_t _Source,mbstate_t * __restrict__ _State) { DBG(); }
int wctob(wint_t _WCh) { DBG(); }
wint_t btowc(int) { DBG(); }
double log2 (double) { DBG(); }
long double exp2l(long double) { DBG(); }
long double cosl(long double) { DBG(); }
long double log2l (long double) { DBG(); }
long double atan2l (long double, long double) { DBG(); }
double remainder (double, double) { DBG(); }


DLLEXPORT_FUNC(void, _assert, (const char *message, const char *file, unsigned line), { DBG(); })

DLLEXPORT_FUNC(uintptr_t, _beginthreadex, (void *security, unsigned stack_size, unsigned (__stdcall *start_address)(void *), void *arglist, unsigned initflag, unsigned *thrdaddr), { DBG(); })
DLLEXPORT_FUNC(errno_t, strerror_s, (char *_Buf, size_t _SizeInBytes, int _ErrNum), { DBG(); })
DLLEXPORT_FUNC(int *, __sys_nerr, (void), { DBG(); })

DLLEXPORT_FUNC(int, _sscanf_l, (const char *buffer, const char *format, _locale_t locale, ...), { DBG(); })
DLLEXPORT_FUNC(int, _isctype, (int _C, int _Type), { DBG(); })
DLLEXPORT_FUNC(const unsigned short*, __pctype_func, (void), { DBG(); return CTypeData; })
DLLEXPORT_FUNC(int, _isctype_l, (int _C,int _Type,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(void, _free_locale, (_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(int, _strcoll_l, (const char *_Str1,const char *_Str2,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(size_t, _strxfrm_l, (char * __restrict__ _Dst,const char * __restrict__ _Src,size_t _MaxCount,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(int, _wcscoll_l, (const wchar_t *_Str1,const wchar_t *_Str2,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(size_t, _wcsxfrm_l, (wchar_t * __restrict__ _Dst,const wchar_t * __restrict__ _Src,size_t _MaxCount,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(int, _iswalpha_l, (wint_t _C,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(int, _iswupper_l, (wint_t _C,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(int, _iswlower_l, (wint_t _C,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(int, _iswdigit_l, (wint_t _C,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(int, _iswxdigit_l, (wint_t _C,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(int, _iswspace_l, (wint_t _C,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(int, _iswpunct_l, (wint_t _C,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(int, _iswalnum_l, (wint_t _C,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(int, _iswprint_l, (wint_t _C,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(int, _iswgraph_l, (wint_t _C,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(int, _iswcntrl_l, (wint_t _C,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(wint_t, _towupper_l, (wint_t _C,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(wint_t, _towlower_l, (wint_t _C,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(int, _toupper_l, (int _C,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(int, _tolower_l, (int _C,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(__int64, _strtoi64_l, (const char *_String,char **_EndPtr,int _Radix,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(unsigned __int64, _strtoui64_l, (const char *_String,char **_EndPtr,int _Radix,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(double, _strtod_l, (const char * __restrict__ _Str,char ** __restrict__ _EndPtr,_locale_t _Locale), { DBG(); })
DLLEXPORT_FUNC(_locale_t, _create_locale, (int _Category,const char *_Locale), { DBG(); return nullptr; })
DLLEXPORT_FUNC(int, ___mb_cur_max_func, (void), { DBG(); })
DLLEXPORT_FUNC(char *,_strdup, (const char *_Src), { DBG(); })
DLLEXPORT_FUNC(struct lconv *, localeconv, (void), { DBG(); })
DLLEXPORT_FUNC(int, _mbtowc_l, (wchar_t * __restrict__ _DstCh,const char * __restrict__ _SrcCh,size_t _SrcSizeInBytes,_locale_t _Locale), { DBG(); return 0; })
DLLEXPORT_FUNC(errno_t, wcrtomb_s, (size_t *_Retval,char *_Dst,size_t _SizeInBytes,wchar_t _Ch,mbstate_t *_State), { DBG(); })
