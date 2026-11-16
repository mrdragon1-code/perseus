using Microsoft.Win32;

namespace Perseus.App;

/// <summary>
/// Voce "PERSEUS" nel menu tasto destro delle cartelle (Esplora file), solo per l'utente corrente
/// (HKCU, nessun privilegio amministratore). Su Windows 11 compare in "Mostra altre opzioni".
/// </summary>
public static class ShellMenu
{
    const string Root = @"Software\Classes\Directory\shell\Perseus";

    static string Exe => Environment.ProcessPath ?? throw new InvalidOperationException("percorso eseguibile sconosciuto");

    public static bool IsRegistered()
    {
        using var k = Registry.CurrentUser.OpenSubKey(Root + @"\shell\1encrypt\command");
        return (k?.GetValue("") as string)?.Contains(Exe, StringComparison.OrdinalIgnoreCase) == true;
    }

    public static void Register()
    {
        Unregister();
        using var root = Registry.CurrentUser.CreateSubKey(Root);
        root.SetValue("MUIVerb", "PERSEUS");
        root.SetValue("Icon", $"\"{Exe}\",0");
        root.SetValue("SubCommands", "");
        Verb(root, "1encrypt", "Cifra cartella", "--encrypt");
        Verb(root, "2decrypt", "Decifra cartella (autenticazione)", "--decrypt");
    }

    static void Verb(RegistryKey root, string key, string label, string arg)
    {
        using var v = root.CreateSubKey(@"shell\" + key);
        v.SetValue("MUIVerb", label);
        v.SetValue("Icon", $"\"{Exe}\",0");
        using var c = v.CreateSubKey("command");
        c.SetValue("", $"\"{Exe}\" {arg} \"%1\"");
    }

    public static void Unregister() => Registry.CurrentUser.DeleteSubKeyTree(Root, throwOnMissingSubKey: false);
}
