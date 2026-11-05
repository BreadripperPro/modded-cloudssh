import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MobileShortcutsManager } from '../frontend/src/mobile-shortcuts-manager';
import { buildDefaultMobileShortcuts } from '../src/mobile-shortcuts-schema';

class MemoryStorage {
  private data = new Map<string, string>();

  getItem(key: string): string | null {
    return this.data.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.data.set(key, value);
  }

  removeItem(key: string): void {
    this.data.delete(key);
  }

  clear(): void {
    this.data.clear();
  }
}

describe('MobileShortcutsManager', () => {
  beforeEach(() => {
    vi.stubGlobal('localStorage', new MemoryStorage());
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('初始状态返回默认 20 个快捷键', () => {
    const manager = new MobileShortcutsManager();
    const defaults = buildDefaultMobileShortcuts().shortcuts;
    expect(manager.getShortcuts()).toEqual(defaults);
  });

  it('setLoggedIn(false) 清空本地缓存并恢复默认配置', () => {
    localStorage.setItem(
      'cloudssh_mobile_shortcuts_v1',
      JSON.stringify({ shortcuts: [{ id: 'f3' }] })
    );

    const manager = new MobileShortcutsManager();
    const listener = vi.fn();
    manager.onChange(listener);

    manager.setLoggedIn(false);
    expect(localStorage.getItem('cloudssh_mobile_shortcuts_v1')).toBeNull();
    expect(manager.getShortcuts()).toEqual(buildDefaultMobileShortcuts().shortcuts);
    expect(listener).toHaveBeenCalled();
  });

  it('setLoggedIn(true) 优先命中本地缓存镜像，随后向云端发起同步', async () => {
    const customList = [
      { id: 'escape', label: 'Esc', type: 'key' as const },
      { id: 'f3', label: 'F3', type: 'key' as const },
      { id: 'delete', label: 'Del', type: 'key' as const },
    ];
    localStorage.setItem(
      'cloudssh_mobile_shortcuts_v1',
      JSON.stringify({ shortcuts: customList })
    );

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ shortcuts: customList }),
    });
    vi.stubGlobal('fetch', fetchMock);

    const manager = new MobileShortcutsManager();
    const updates: Array<Array<{ id: string }>> = [];
    manager.onChange((shortcuts) => {
      updates.push(shortcuts.map((s) => ({ id: s.id })));
    });

    manager.setLoggedIn(true);

    // 同步读取到本地缓存
    expect(manager.getShortcuts().map((s) => s.id)).toEqual(['escape', 'f3', 'delete']);

    await manager.syncFromCloud();
    expect(fetchMock).toHaveBeenCalledWith('/api/user/mobile-shortcuts', { method: 'GET' });
  });

  it('云端返回 shortcuts: null 时恢复默认设置并清除本地缓存', async () => {
    const customList = [{ id: 'f3', label: 'F3', type: 'key' as const }];
    localStorage.setItem(
      'cloudssh_mobile_shortcuts_v1',
      JSON.stringify({ shortcuts: customList })
    );

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ shortcuts: null }),
    });
    vi.stubGlobal('fetch', fetchMock);

    const manager = new MobileShortcutsManager();
    manager.setLoggedIn(true);
    await manager.syncFromCloud();

    expect(localStorage.getItem('cloudssh_mobile_shortcuts_v1')).toBeNull();
    expect(manager.getShortcuts()).toEqual(buildDefaultMobileShortcuts().shortcuts);
  });

  it('自定义按键输入行正确配置名称输入框与内容输入框样式，防止被挤压', async () => {
    const { readFileSync } = await import('node:fs');
    const tsSource = readFileSync(
      new URL('../frontend/src/mobile-shortcuts-manager.ts', import.meta.url),
      'utf8'
    );
    const cssSource = readFileSync(
      new URL('../frontend/src/style.css', import.meta.url),
      'utf8'
    );

    // 源码断言守护：label 输入框必须使用 !w-24 shrink-0 锁定宽度，使用 text-[11px] 小字号
    expect(tsSource).toMatch(/customLabelInput\.className\s*=\s*'terminal-input\s+!w-24\s+shrink-0\s+text-\[11px\]/);
    expect(tsSource).toMatch(/customValueInput\.className\s*=\s*'terminal-input\s+flex-1\s+min-w-0\s+text-\[11px\]/);

    // CSS 规则守护：显式声明小字号 11px !important 与固定宽度 96px
    expect(cssSource).toMatch(/#mobile-shortcut-custom-label,\s*#mobile-shortcut-custom-value\s*\{[\s\S]*?font-size:\s*11px\s*!important;/);
    expect(cssSource).toMatch(/#mobile-shortcut-custom-label\s*\{[\s\S]*?width:\s*96px;[\s\S]*?flex:\s*0\s+0\s+96px;/);
  });
});
