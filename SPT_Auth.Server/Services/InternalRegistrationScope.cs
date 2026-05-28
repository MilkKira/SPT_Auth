namespace SPT_Auth.Server.Services;

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
            if (disposed)
            {
                return;
            }

            Depth.Value = Math.Max(0, Depth.Value - 1);
            disposed = true;
        }
    }
}
