namespace Tunneld.Net;

public static class VersionInfo
{
    public static string Version { get; set; } = "dev";
    public static string Commit { get; set; } = "unknown";
    public static string Date { get; set; } = "unknown";

    public static string String() => $"{Version} ({Commit}, {Date})";
}
