const std = @import("std");
const ecvrf = @import("ecvrf.zig");

fn parseHexDigit(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

fn hexDecode(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidHex;
    const len = hex.len / 2;
    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);
    for (0..len) |i| {
        const hi = parseHexDigit(hex[2 * i]) orelse return error.InvalidHex;
        const lo = parseHexDigit(hex[2 * i + 1]) orelse return error.InvalidHex;
        buf[i] = (hi << 4) | lo;
    }
    return buf;
}

fn hexEncode(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const charset = "0123456789abcdef";
    const hex = try allocator.alloc(u8, bytes.len * 2);
    for (0..bytes.len) |i| {
        hex[2 * i] = charset[bytes[i] >> 4];
        hex[2 * i + 1] = charset[bytes[i] & 0x0f];
    }
    return hex;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const so: std.fs.File = .stdout();
    const se: std.fs.File = .stderr();

    if (args.len < 2) {
        se.writeAll("usage: ecvrf-cli prove <sk> <alpha> | verify <pk> <pi> <alpha> | derive-pk <sk>\n") catch {};
        std.process.exit(2);
    }

    if (std.mem.eql(u8, args[1], "prove")) {
        if (args.len < 4) std.process.exit(2);
        const sk = hexDecode(allocator, args[2]) catch std.process.exit(2);
        defer allocator.free(sk);
        const alpha = hexDecode(allocator, args[3]) catch std.process.exit(2);
        defer allocator.free(alpha);

        const pi = ecvrf.prove(sk, alpha) catch std.process.exit(1);
        const pi_hex = try hexEncode(allocator, &pi);
        defer allocator.free(pi_hex);
        so.writeAll(pi_hex) catch {};
        so.writeAll("\n") catch {};
    } else if (std.mem.eql(u8, args[1], "verify")) {
        if (args.len < 5) std.process.exit(2);
        const pk = hexDecode(allocator, args[2]) catch std.process.exit(2);
        defer allocator.free(pk);
        const pi = hexDecode(allocator, args[3]) catch std.process.exit(2);
        defer allocator.free(pi);
        const alpha = hexDecode(allocator, args[4]) catch std.process.exit(2);
        defer allocator.free(alpha);

        if (ecvrf.verify(pk, pi, alpha)) |beta| {
            const beta_hex = try hexEncode(allocator, &beta);
            defer allocator.free(beta_hex);
            so.writeAll(beta_hex) catch {};
            so.writeAll("\n") catch {};
        } else {
            std.process.exit(1);
        }
    } else if (std.mem.eql(u8, args[1], "derive-pk")) {
        if (args.len < 3) std.process.exit(2);
        const sk = hexDecode(allocator, args[2]) catch std.process.exit(2);
        defer allocator.free(sk);

        const pk = ecvrf.derivePublicKey(sk) catch std.process.exit(1);
        const pk_hex = try hexEncode(allocator, &pk);
        defer allocator.free(pk_hex);
        so.writeAll(pk_hex) catch {};
        so.writeAll("\n") catch {};
    } else {
        se.writeAll("unknown command\n") catch {};
        std.process.exit(2);
    }
}
