using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Perseus.App.Native;

namespace Perseus.App.ViewModels;

public enum AuthState { Locked, Scanning, Authorized, Hostile }

public sealed record LogEntry(string Time, string Tag, string Text, Brush Color);

public partial class MainViewModel : ObservableObject
{
    static Brush Res(string k) => (Brush)Application.Current.Resources[k];

    [ObservableProperty] private AuthState state = AuthState.Locked;
    [ObservableProperty] private string stateLabel = "LOCKED";
    [ObservableProperty] private string stateDetail = "Autenticazione richiesta";
    [ObservableProperty] private Brush stateBrush = Brushes.Gray;
    [ObservableProperty] private bool setupDone = true;
    [ObservableProperty] private bool unlocked;
    [ObservableProperty] private bool busy;
    [ObservableProperty] private string cameraLabel = "NESSUN SENSORE";
    [ObservableProperty] private WriteableBitmap? frame;
    [ObservableProperty] private string allowList = "";
    [ObservableProperty] private string lockoutText = "";

    public ObservableCollection<LogEntry> Log { get; } = [];
    public ObservableCollection<FolderStatus> Folders { get; } = [];
    public ObservableCollection<CameraDesc> Cameras { get; } = [];

    readonly DispatcherTimer frameTimer = new() { Interval = TimeSpan.FromMilliseconds(33) };
    readonly DispatcherTimer hostileTimer = new() { Interval = TimeSpan.FromSeconds(4) };
    byte[] frameBuf = new byte[1920 * 1080 * 4];
    ulong frameSeq;

    public MainViewModel()
    {
        frameTimer.Tick += (_, _) => PollFrame();
        hostileTimer.Tick += (_, _) => { hostileTimer.Stop(); if (State == AuthState.Hostile) SetState(AuthState.Locked); };
        SetState(AuthState.Locked);
    }

    // ---------- infrastruttura ----------

    void Write(string tag, string text, string color = "Text") =>
        Log.Insert(0, new LogEntry(DateTime.Now.ToString("HH:mm:ss"), tag, text, Res(color)));

    void SetState(AuthState s, string? detail = null)
    {
        State = s;
        (StateLabel, StateBrush, StateDetail) = s switch
        {
            AuthState.Authorized => ("AUTORIZZATO", Res("Ok"), "Accesso concesso — cartelle in chiaro"),
            AuthState.Hostile => ("NON AUTORIZZATO", Res("Hostile"), "OSTILE — accesso negato"),
            AuthState.Scanning => ("VERIFICA", Res("Accent"), "Analisi in corso…"),
            _ => ("LOCKED", Res("Dim"), "Autenticazione richiesta"),
        };
        if (detail != null) StateDetail = detail;
        if (s == AuthState.Hostile) hostileTimer.Start();
    }

    /// Esegue una chiamata al core fuori dal thread UI e gestisce gli errori.
    async Task<T?> Run<T>(string tag, Func<T> f)
    {
        Busy = true;
        try { return await Task.Run(f); }
        catch (PerseusException ex) { Write(tag, ex.Message, "Warn"); return default; }
        finally { Busy = false; }
    }

    void ShowReport(string what, Report? r)
    {
        if (r == null) return;
        Write("VAULT", $"{what}: {r.Processed} file", r.Failed.Count == 0 ? "Ok" : "Warn");
        foreach (var f in r.Failed.Take(20)) Write("VAULT", $"✖ {f.Path} — {f.Error}", "Warn");
    }

    public async Task InitAsync()
    {
        await Run("CORE", () => { Core.Init(); return 0; });
        await RefreshAsync();
        Write("CORE", "PERSEUS online", "Accent");
        await RefreshCamerasAsync();
        var trusted = Cameras.FirstOrDefault(c => c.Trusted);
        if (trusted != null) await OpenCameraAsync(trusted);
        else Write("SENSOR", "SENSORE NON ATTENDIBILE: nessuna camera iVCam trovata", "Warn");
    }

    async Task RefreshAsync()
    {
        var s = await Run("CORE", Core.GetStatus);
        if (s == null) return;
        SetupDone = s.SetupDone;
        Unlocked = s.Unlocked;
        AllowList = string.Join(", ", s.CameraAllow);
        LockoutText = s.LockoutSecs > 0 ? $"LOCKOUT {s.LockoutSecs}s" : "";
        Folders.Clear();
        foreach (var f in s.Folders) Folders.Add(f);
        if (s.JournalPending) Write("VAULT", "Operazione interrotta in sospeso: verrà completata al prossimo sblocco", "Warn");
        if (s.Unlocked && State != AuthState.Authorized) SetState(AuthState.Authorized);
        if (!s.Unlocked && State == AuthState.Authorized) SetState(AuthState.Locked);
    }

    // ---------- autenticazione ----------

    public async Task SetupAsync(string pw1, string pw2)
    {
        if (pw1 != pw2) { Write("SETUP", "Le password non coincidono", "Warn"); return; }
        var ok = await Run("SETUP", () => { Core.Setup(pw1); return true; });
        if (ok)
        {
            Write("SETUP", "Chiave master creata. Conserva la password: è l'UNICO recupero.", "Ok");
            SetState(AuthState.Authorized);
        }
        await RefreshAsync();
    }

    public async Task UnlockPasswordAsync(string pw)
    {
        if (string.IsNullOrEmpty(pw)) return;
        SetState(AuthState.Scanning, "Verifica password (Argon2id)…");
        bool? ok = await Run<bool?>("AUTH", () => Core.UnlockPassword(pw));
        if (ok == true)
        {
            Write("AUTH", "PASSWORD → AUTORIZZATO", "Ok");
            SetState(AuthState.Authorized);
            ShowReport("Decifrati", await Run("VAULT", Core.DecryptAll));
        }
        else if (ok == false)
        {
            Write("AUTH", "PASSWORD → NON AUTORIZZATO", "Hostile");
            SetState(AuthState.Hostile, "Password errata — tentativo registrato");
        }
        else
        {
            SetState(AuthState.Hostile, "Accesso temporaneamente bloccato");
        }
        await RefreshAsync();
    }

    [RelayCommand]
    async Task LockAsync()
    {
        ShowReport("Cifrati", await Run("VAULT", Core.Lock));
        Write("AUTH", "Vault bloccato, chiave rimossa dalla memoria", "Accent");
        SetState(AuthState.Locked);
        await RefreshAsync();
    }

    // ---------- cartelle ----------

    [RelayCommand]
    async Task AddFolderAsync()
    {
        var dlg = new Microsoft.Win32.OpenFolderDialog { Title = "Cartella da proteggere" };
        if (dlg.ShowDialog() != true) return;
        var path = dlg.FolderName;
        if (MessageBox.Show($"Aggiungere e CIFRARE subito:\n{path}\n\nProva prima su una cartella di test con copie dei file.",
                "PERSEUS", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;
        if (await Run("VAULT", () => { Core.AddFolder(path); return true; }))
        {
            Write("VAULT", $"Cartella protetta: {path}", "Accent");
        }
        await RefreshAsync();
    }

    [RelayCommand]
    async Task RemoveFolderAsync(FolderStatus? f)
    {
        if (f == null) return;
        ShowReport($"Rimossa (decifrata) {f.Path}", await Run("VAULT", () => Core.RemoveFolder(f.Path)));
        await RefreshAsync();
    }

    [RelayCommand]
    async Task EncryptAllAsync() { ShowReport("Cifrati", await Run("VAULT", Core.EncryptAll)); await RefreshAsync(); }

    [RelayCommand]
    async Task DecryptAllAsync() { ShowReport("Decifrati", await Run("VAULT", Core.DecryptAll)); await RefreshAsync(); }

    // ---------- menu tasto destro ----------

    [ObservableProperty] private bool shellRegistered = ShellMenu.IsRegistered();

    [RelayCommand]
    void ToggleShell()
    {
        if (ShellRegistered) ShellMenu.Unregister(); else ShellMenu.Register();
        ShellRegistered = ShellMenu.IsRegistered();
        Write("SHELL", ShellRegistered
            ? "Menu tasto destro attivo: clic destro su una cartella → PERSEUS (Win 11: 'Mostra altre opzioni')"
            : "Menu tasto destro rimosso", "Accent");
    }

    // ---------- sensori ----------

    [RelayCommand]
    async Task RefreshCamerasAsync()
    {
        var list = await Run("SENSOR", Core.ListCameras);
        Cameras.Clear();
        foreach (var c in list ?? []) Cameras.Add(c);
        foreach (var c in Cameras.Where(c => c.Verdict.Kind == "Blocked"))
            Write("SENSOR", $"Ignorata: {c.Name} ({c.Verdict.Reason})", "Hostile");
    }

    [RelayCommand]
    async Task OpenCameraAsync(CameraDesc? c)
    {
        if (c == null) return;
        frameTimer.Stop();
        if (await Run("SENSOR", () => { Core.OpenCamera(c.Index); return true; }))
        {
            frameSeq = 0;
            CameraLabel = $"SENSOR // {c.Name.ToUpperInvariant()}";
            Write("SENSOR", $"Sensore attivo: {c.Name}", "Accent");
            frameTimer.Start();
        }
        else CameraLabel = "SENSORE NON ATTENDIBILE";
    }

    [RelayCommand]
    async Task SaveAllowListAsync()
    {
        var list = AllowList.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (await Run("SENSOR", () => { Core.SetCameraAllow(list); return true; }))
            Write("SENSOR", $"Allowlist: {string.Join(", ", list)}", "Accent");
        await RefreshCamerasAsync();
    }

    void PollFrame()
    {
        try
        {
            int rc = Core.TryFrame(frameBuf, ref frameSeq, out var w, out var h);
            if (rc == -2) { frameBuf = new byte[w * h * 4]; return; }
            if (rc != 1) return;
            if (Frame == null || Frame.PixelWidth != w || Frame.PixelHeight != h)
                Frame = new WriteableBitmap((int)w, (int)h, 96, 96, PixelFormats.Bgra32, null);
            Frame.WritePixels(new Int32Rect(0, 0, (int)w, (int)h), frameBuf, (int)w * 4, 0);
        }
        catch (PerseusException ex)
        {
            frameTimer.Stop();
            CameraLabel = "SEGNALE PERSO";
            Write("SENSOR", ex.Message, "Warn");
        }
    }

    public void Shutdown()
    {
        frameTimer.Stop();
        try { Core.CloseCamera(); } catch (PerseusException) { }
    }
}
