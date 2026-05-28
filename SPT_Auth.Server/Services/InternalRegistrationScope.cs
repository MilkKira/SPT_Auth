namespace SPT_Auth.Server.Services;

/**
 * Patch 重入保护上下文 / 内部调用旁路开关
 * 
 * 在代码内部调用 LauncherController.Login/Register 时，临时绕过你写的 Harmony Patch，避免递归和逻辑冲突。
 */
public static class InternalRegistrationScope
{
    private static readonly AsyncLocal<int> Depth = new();

    public static bool IsActive => Depth.Value > 0;

    public static IDisposable Begin()
    {
        Depth.Value++;
        return new Scope();
    }

    private sealed class Scope : IDisposable
    {
        private bool disposed;

        public void Dispose()
        {
            if (disposed) return;

            Depth.Value = Math.Max(0, Depth.Value - 1);
            disposed = true;
        }
    }
}