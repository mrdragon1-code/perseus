using System.Windows;
using System.Windows.Input;
using Perseus.App.ViewModels;

namespace Perseus.App;

public partial class MainWindow : Window
{
    MainViewModel Vm => (MainViewModel)DataContext;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) => await Vm.InitAsync();
        Closing += (_, _) => Vm.Shutdown();
    }

    async void Unlock_Click(object sender, RoutedEventArgs e)
    {
        var pw = PwBox.Password;
        PwBox.Clear();
        await Vm.UnlockPasswordAsync(pw);
    }

    void PwBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) Unlock_Click(sender, e);
    }

    async void Setup_Click(object sender, RoutedEventArgs e)
    {
        var (a, b) = (SetupPw1.Password, SetupPw2.Password);
        SetupPw1.Clear();
        SetupPw2.Clear();
        await Vm.SetupAsync(a, b);
    }
}
