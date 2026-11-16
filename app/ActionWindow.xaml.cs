using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Perseus.App.Native;

namespace Perseus.App;

/// <summary>Finestra compatta aperta dal menu tasto destro: "Cifra" o "Decifra" una cartella.</summary>
public partial class ActionWindow : Window
{
    readonly bool encrypt;
    readonly string path;

    static Brush Res(string k) => (Brush)Application.Current.Resources[k];

    public ActionWindow(bool encrypt, string path)
    {
        InitializeComponent();
        this.encrypt = encrypt;
        this.path = path;
        Heading.Text = encrypt ? "▲ PERSEUS // CIFRA CARTELLA" : "▲ PERSEUS // DECIFRA CARTELLA";
        PathText.Text = path;
        Loaded += async (_, _) => await StartAsync();
    }

    void Show(string state, string brush, string detail)
    {
        StateText.Text = state;
        StateText.Foreground = Res(brush);
        Outline.BorderBrush = Res(brush);
        DetailText.Text = detail;
    }

    async Task<T?> Busy<T>(Func<T> f)
    {
        Progress.Visibility = Visibility.Visible;
        try { return await Task.Run(f); }
        finally { Progress.Visibility = Visibility.Collapsed; }
    }

    async Task StartAsync()
    {
        try
        {
            await Busy(() => { Core.Init(); return 0; });
            if (!await Busy(Core.IsSetup))
            {
                Show("NON CONFIGURATO", "Warn", "Apri PERSEUS e crea la password prima di usare il menu.");
                OpenMain.Visibility = Visibility.Visible;
                return;
            }
            if (encrypt)
            {
                Show("CIFRATURA…", "Accent", "Non chiudere questa finestra.");
                ShowReport(await Busy(() => Core.EncryptFolderQuick(path)), "cifrati");
            }
            else
            {
                Show("LOCKED", "Dim", "Autenticazione richiesta per decifrare.");
                AuthPanel.Visibility = Visibility.Visible;
                PwBox.Focus();
            }
        }
        catch (PerseusException ex)
        {
            Show("ERRORE", "Warn", ex.Message);
        }
    }

    async void Auth_Click(object sender, RoutedEventArgs e)
    {
        var pw = PwBox.Password;
        PwBox.Clear();
        if (pw.Length == 0) return;
        AuthButton.IsEnabled = false;
        try
        {
            Show("VERIFICA", "Accent", "Verifica password (Argon2id)…");
            if (!await Busy(() => Core.UnlockPassword(pw)))
            {
                Show("NON AUTORIZZATO", "Hostile", "Password errata — tentativo registrato.");
                return;
            }
            AuthPanel.Visibility = Visibility.Collapsed;
            Show("AUTORIZZATO", "Ok", "Decifratura in corso…");
            var rep = await Busy(() =>
            {
                try { return Core.DecryptFolder(path); }
                finally { Core.ForgetKey(); }
            });
            ShowReport(rep, "decifrati");
        }
        catch (PerseusException ex)
        {
            Show("NON AUTORIZZATO", "Hostile", ex.Message);
        }
        finally
        {
            AuthButton.IsEnabled = true;
        }
    }

    void ShowReport(Report? r, string verb)
    {
        if (r == null) return;
        if (r.Failed.Count == 0)
        {
            Show("COMPLETATO", "Ok", $"{r.Processed} file {verb}.");
            var t = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
            t.Tick += (_, _) => { t.Stop(); Close(); };
            t.Start();
        }
        else
        {
            Show("COMPLETATO CON ERRORI", "Warn", $"{r.Processed} file {verb}, {r.Failed.Count} non riusciti:");
            Failures.ItemsSource = r.Failed.Select(f => $"{f.Path} — {f.Error}");
            Failures.Visibility = Visibility.Visible;
        }
    }

    void PwBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) Auth_Click(sender, e);
    }

    void OpenMain_Click(object sender, RoutedEventArgs e)
    {
        new MainWindow().Show();
        Close();
    }

    void Close_Click(object sender, RoutedEventArgs e) => Close();
}
