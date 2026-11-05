/**
 * 抽屉面板触摸右滑关闭（移动端）
 *
 * 在面板头部按住向右拖动，面板跟随手指平移；松手时位移或速度达标即走
 * 原有的 hide()/close() 关闭语义（含 AGENTS.md #37 的在途传输中断），
 * 未达标则以弹簧曲线回弹原位。仅粗指针触屏设备挂载，桌面端行为不变。
 *
 * 手势只在面板头部区域生效：既避开 iOS Safari 屏幕左缘的系统返回手势，
 * 也不与列表纵向滚动、面包屑横向滚动竞争。
 */

export interface DrawerSwipeOptions {
  /** 手势生效的头部区域选择器 */
  headerSelector: string;
  /** 达标关闭时回调（应调用面板既有的 hide/close） */
  onClose: () => void;
}

/** 横向位移超过该值即判定为拖拽意图（小于它则仍是点按/纵向滚动） */
const GESTURE_SLOP_PX = 10;
/** 松手时位移超过该值直接关闭 */
const CLOSE_DISTANCE_PX = 96;
/** 快速轻扫的速度阈值（px/ms），位移满 32px 才允许走速度判定 */
const CLOSE_VELOCITY_PX_PER_MS = 0.45;
const FLICK_MIN_DISTANCE_PX = 32;

export function attachDrawerSwipeToClose(panel: HTMLElement, options: DrawerSwipeOptions): void {
  if (!window.matchMedia?.('(hover: none) and (pointer: coarse)').matches) return;

  let tracking = false;
  let dragging = false;
  let touchId = -1;
  let startX = 0;
  let startY = 0;
  let lastX = 0;
  let lastTime = 0;
  let velocity = 0;

  const findTouch = (list: TouchList): Touch | null => {
    for (let i = 0; i < list.length; i++) {
      const candidate = list.item(i);
      if (candidate && candidate.identifier === touchId) return candidate;
    }
    return null;
  };

  panel.addEventListener(
    'touchstart',
    (e: TouchEvent) => {
      if (e.touches.length !== 1) return;
      const target = e.target as HTMLElement | null;
      const header = target?.closest?.(options.headerSelector);
      if (!header || !panel.contains(header)) return;
      const touch = e.touches.item(0)!;
      tracking = true;
      dragging = false;
      touchId = touch.identifier;
      startX = touch.clientX;
      startY = touch.clientY;
      lastX = touch.clientX;
      lastTime = e.timeStamp;
      velocity = 0;
    },
    { passive: true }
  );

  panel.addEventListener(
    'touchmove',
    (e: TouchEvent) => {
      if (!tracking) return;
      const touch = findTouch(e.touches);
      if (!touch) return;
      const dx = touch.clientX - startX;
      const dy = touch.clientY - startY;

      if (!dragging) {
        if (dx > GESTURE_SLOP_PX && dx > Math.abs(dy) * 1.2) {
          dragging = true;
          panel.style.transition = 'none';
        } else {
          // 纵向意图明确后交还滚动，本轮不再介入
          if (Math.abs(dy) > GESTURE_SLOP_PX) tracking = false;
          return;
        }
      }

      e.preventDefault();
      const dt = e.timeStamp - lastTime;
      if (dt > 0) {
        velocity = velocity * 0.7 + ((touch.clientX - lastX) / dt) * 0.3;
      }
      lastX = touch.clientX;
      lastTime = e.timeStamp;
      panel.style.transform = `translateX(${Math.max(0, dx)}px)`;
    },
    { passive: false }
  );

  const finish = (): void => {
    if (!tracking) return;
    tracking = false;
    if (!dragging) return;
    dragging = false;

    const dx = Math.max(0, lastX - startX);
    const shouldClose =
      dx >= CLOSE_DISTANCE_PX || (dx >= FLICK_MIN_DISTANCE_PX && velocity >= CLOSE_VELOCITY_PX_PER_MS);

    if (shouldClose) {
      // 保留当前拖拽位置的内联 transform，只交还过渡曲线，
      // 让 onClose 设置的 translateX(100%) 从手指位置平滑收起
      panel.style.transition = '';
      void panel.offsetWidth;
      options.onClose();
      return;
    }

    // 弹簧回弹到原位，结束后清理内联样式交还 CSS 控制
    panel.style.transition = 'transform var(--motion-normal) var(--spring-ease)';
    panel.style.transform = 'translateX(0)';
    let settled = false;
    const cleanup = (): void => {
      if (settled) return;
      settled = true;
      panel.removeEventListener('transitionend', cleanup);
      panel.style.transition = '';
      panel.style.transform = '';
    };
    panel.addEventListener('transitionend', cleanup);
    window.setTimeout(cleanup, 320);
  };

  panel.addEventListener('touchend', finish, { passive: true });
  panel.addEventListener('touchcancel', finish, { passive: true });
}
