using System.Windows;

namespace Perseus.App;

/// <summary>
/// Argomenti:
///   (nessuno)              console principale
///   --encrypt "cartella"   menu contestuale: cifra (nessuna autenticazione)
///   --decrypt "cartella"   menu contestuale: decifra (autenticazione)
///   --register-shell       aggiunge "PERSEUS" al menu tasto destro delle cartelle
///   --unregister-shell     lo rimuove
/// </summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += (_, ex) =>
        {
            MessageBox.Show(ex.Exception.Message, "PERSEUS — errore", MessageBoxButton.OK, MessageBoxImage.Error);
            ex.Handled = true;
        };
        base.OnStartup(e);

        var a = e.Args;
        switch (a.FirstOrDefault())
        {
            case "--register-shell":
                ShellMenu.Register();
                Shutdown();
                return;
            case "--unregister-shell":
                ShellMenu.Unregister();
                Shutdown();
                return;
            case "--encrypt" or "--decrypt" when a.Length >= 2:
                new ActionWindow(a[0] == "--encrypt", a[1]).Show();
                return;
            default:
                new MainWindow().Show();
                return;
        }
    }
}
