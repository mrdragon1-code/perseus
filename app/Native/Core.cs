using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Perseus.App.Native;

public sealed class PerseusException(string message) : Exception(message);

public sealed record FolderStatus(string Path, int Encrypted, int Plain);
public sealed record Status(bool SetupDone, bool Unlocked, long LockoutSecs, bool JournalPending,
                            List<FolderStatus> Folders, List<string> CameraAllow);
public sealed record Failure(string Path, string Error);
public sealed record Report(int Processed, List<Failure> Failed);
public sealed record Verdict(string Kind, string? Reason);
public sealed record CameraDesc(uint Index, string Name, string Misc, Verdict Verdict)
{
    public bool Trusted => Verdict.Kind == "Trusted";
    public string VerdictLabel => Verdict.Kind switch
    {
        "Trusted" => "ATTENDIBILE",
        "Blocked" => "BLOCCATA",
        _ => "NON ATTENDIBILE",
    };
}

/// <summary>
/// Wrapper sicuro sopra le funzioni generate da csbindgen.
/// Nota: l'errore è thread-local nel core, quindi ogni chiamata legge l'errore sullo stesso thread.
/// </summary>
public static unsafe class Core
{
    static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        NumberHandling = JsonNumberHandling.AllowReadingFromString,
    };

    static string? Take(byte* p)
    {
        if (p == null) return null;
        try { return Marshal.PtrToStringUTF8((IntPtr)p); }
        finally { NativeMethods.prs_free_string(p); }
    }

    static string LastError() => Take(NativeMethods.prs_last_error()) ?? "errore sconosciuto";

    static int Check(int rc) => rc < 0 ? throw new PerseusException(LastError()) : rc;

    static T Parse<T>(byte* p)
    {
        var s = Take(p) ?? throw new PerseusException(LastError());
        return JsonSerializer.Deserialize<T>(s, Json) ?? throw new PerseusException("risposta vuota dal core");
    }

    /// Stringa UTF-8 terminata da NUL; il chiamante deve azzerarla dopo l'uso.
    static byte[] Utf8Z(string s)
    {
        var b = new byte[Encoding.UTF8.GetByteCount(s) + 1];
        Encoding.UTF8.GetBytes(s, 0, s.Length, b, 0);
        return b;
    }

    static int WithArg(string s, Func<IntPtr, int> f)
    {
        var b = Utf8Z(s);
        try { fixed (byte* p = b) return f((IntPtr)p); }
        finally { CryptographicOperations.ZeroMemory(b); }
    }

    static T WithArg<T>(string s, Func<IntPtr, T> f)
    {
        var b = Utf8Z(s);
        try { fixed (byte* p = b) return f((IntPtr)p); }
        finally { CryptographicOperations.ZeroMemory(b); }
    }

    public static void Init() => Check(NativeMethods.prs_init(null));

    public static Status GetStatus() => Parse<Status>(NativeMethods.prs_status_json());

    public static void Setup(string password) =>
        WithArg(password, p => Check(NativeMethods.prs_setup((byte*)p)));

    /// true = AUTORIZZATO, false = NON AUTORIZZATO. Eccezione su lockout/errore.
    public static bool UnlockPassword(string password) =>
        WithArg(password, p => Check(NativeMethods.prs_unlock_password((byte*)p))) == 1;

    public static Report Lock() => Parse<Report>(NativeMethods.prs_lock());
    public static Report EncryptAll() => Parse<Report>(NativeMethods.prs_encrypt_all());
    public static Report DecryptAll() => Parse<Report>(NativeMethods.prs_decrypt_all());

    public static void AddFolder(string path) =>
        WithArg(path, p => Check(NativeMethods.prs_folder_add((byte*)p)));

    public static Report RemoveFolder(string path) =>
        WithArg(path, p => Parse<Report>(NativeMethods.prs_folder_remove((byte*)p)));

    public static bool IsSetup() => Check(NativeMethods.prs_is_setup()) == 1;

    /// Menu contestuale "Cifra" (nessuna autenticazione: cifrare non espone dati).
    public static Report EncryptFolderQuick(string path) =>
        WithArg(path, p => Parse<Report>(NativeMethods.prs_encrypt_folder_quick((byte*)p)));

    /// Menu contestuale "Decifra" (richiede sblocco).
    public static Report DecryptFolder(string path) =>
        WithArg(path, p => Parse<Report>(NativeMethods.prs_decrypt_folder((byte*)p)));

    public static void ForgetKey() => Check(NativeMethods.prs_forget_key());

    public static void SetCameraAllow(IEnumerable<string> allow) =>
        WithArg(JsonSerializer.Serialize(allow), p => Check(NativeMethods.prs_set_camera_allow((byte*)p)));

    public static List<CameraDesc> ListCameras() => Parse<List<CameraDesc>>(NativeMethods.prs_camera_list_json());

    public static void OpenCamera(uint index) => Check(NativeMethods.prs_camera_open(index));
    public static void CloseCamera() => Check(NativeMethods.prs_camera_close());

    /// 1 = nuovo frame in buf, 0 = niente di nuovo, -2 = buffer troppo piccolo (w/h validi).
    public static int TryFrame(byte[] buf, ref ulong seq, out uint w, out uint h)
    {
        uint ww, hh;
        ulong s = seq;
        int rc;
        fixed (byte* p = buf) rc = NativeMethods.prs_camera_frame(p, (nuint)buf.Length, &ww, &hh, &s);
        w = ww; h = hh; seq = s;
        return rc == -1 ? throw new PerseusException(LastError()) : rc;
    }
}
