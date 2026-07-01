import { afterEach, describe, expect, it } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";

afterEach(() => {
  clearMocks();
});

describe("Tauri IPC contract", () => {
  it("invokes connect_with_auth with expected credentials payload", async () => {
    mockIPC((cmd, args) => {
      if (cmd === "connect_with_auth") {
        expect(args).toMatchObject({
          profileId: "profile-abc",
          username: "alice",
          password: "secret",
        });
        return null;
      }
      return null;
    });

    await invoke("connect_with_auth", {
      profileId: "profile-abc",
      username: "alice",
      password: "secret",
    });
  });

  it("invokes delete_profile with expected payload", async () => {
    let deleteCalled = false;

    mockIPC((cmd, args) => {
      if (cmd === "delete_profile") {
        expect(args).toMatchObject({ profileId: "profile-123" });
        deleteCalled = true;
        return null;
      }
      return null;
    });

    await invoke("delete_profile", { profileId: "profile-123" });
    expect(deleteCalled).toBe(true);
  });

  it("invokes force_rekey and export_logs", async () => {
    mockIPC((cmd) => {
      if (cmd === "force_rekey") {
        return null;
      }
      if (cmd === "export_logs") {
        return "/tmp/hpn_logs_20260101_120000.txt";
      }
      return null;
    });

    await invoke("force_rekey");
    const path = await invoke<string>("export_logs");
    expect(path).toContain("hpn_logs_");
  });
});
