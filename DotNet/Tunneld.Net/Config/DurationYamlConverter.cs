using System.Globalization;
using YamlDotNet.Core;
using YamlDotNet.Core.Events;
using YamlDotNet.Serialization;

namespace Tunneld.Net.Config;

public sealed class DurationYamlConverter : IYamlTypeConverter
{
    public bool Accepts(Type type) => type == typeof(TimeSpan);

    public object? ReadYaml(IParser parser, Type type, ObjectDeserializer rootDeserializer)
    {
        var scalar = parser.Consume<Scalar>().Value;
        if (string.IsNullOrWhiteSpace(scalar) || scalar == "0")
        {
            return TimeSpan.Zero;
        }

        if (TimeSpan.TryParse(scalar, CultureInfo.InvariantCulture, out var parsed))
        {
            return parsed;
        }

        var suffix = scalar[^1];
        if (!double.TryParse(scalar[..^1], NumberStyles.Float, CultureInfo.InvariantCulture, out var value))
        {
            throw new YamlException($"invalid duration {scalar}");
        }

        return suffix switch
        {
            's' => TimeSpan.FromSeconds(value),
            'm' => TimeSpan.FromMinutes(value),
            'h' => TimeSpan.FromHours(value),
            _ => throw new YamlException($"invalid duration suffix {suffix}"),
        };
    }

    public void WriteYaml(IEmitter emitter, object? value, Type type, ObjectSerializer serializer)
    {
        var duration = (TimeSpan)(value ?? TimeSpan.Zero);
        emitter.Emit(new Scalar(duration.ToString()));
    }
}
