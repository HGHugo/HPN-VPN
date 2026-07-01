import { afterEach, describe, expect, it } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";

afterEach(() => {
  clearMocks();
});

describe("Tauri IPC contract", () => {
  it("invokes connect with profileId argument", async () => {
    mockIPC((cmd, args) => {
      if (cmd === "connect") {
        expect(args).toMatchObject({ profileId: "profile-123" });
        return null;
      }
      return null;
    });

    await invoke("connect", { profileId: "profile-123" });
  });

  it("invokes save_profile with camelCase payload", async () => {
    const profile = {
      name: "Work",
      server: "vpn.example.com",
      port: 51820,
      serverPublicKey: "SGVsbG8=",
      securityLevel: "standard",
    };

    mockIPC((cmd, args) => {
      if (cmd === "save_profile") {
        expect(args).toMatchObject({ profile });
        return {
          id: "generated-id",
          ...profile,
          verified: false,
          requiresAuth: false,
          username: null,
          splitTunnel: null,
          serverKemPublicKey: null,
        };
      }
      return null;
    });

    const result = await invoke("save_profile", { profile });
    expect(result).toBeTruthy();
  });

  it("invokes save_settings and export_logs commands", async () => {
    const settings = {
      darkMode: true,
      autoReconnect: true,
      killSwitch: true,
      autoRekey: true,
      language: "EN",
      keepaliveInterval: 25,
      connectionTimeout: 30,
    };

    let exportCalled = false;

    mockIPC((cmd, args) => {
      if (cmd === "save_settings") {
        expect(args).toMatchObject({ settings });
        return null;
      }
      if (cmd === "export_logs") {
        exportCalled = true;
        return "/tmp/hpn_logs_20260101_120000.txt";
      }
      return null;
    });

    await invoke("save_settings", { settings });
    const exported = await invoke<string>("export_logs");

    expect(exported).toContain("hpn_logs_");
    expect(exportCalled).toBe(true);
  });
});
