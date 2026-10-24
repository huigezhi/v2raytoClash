/** 读取文本文件内容并填入文本框 */
export function loadFileInto(file: File, textarea: HTMLTextAreaElement): Promise<void> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      textarea.value = String(reader.result ?? '');
      resolve();
    };
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file);
  });
}

/** 复制文本到剪贴板；file:// 下 clipboard API 可能不可用，降级 execCommand */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // 继续尝试降级方案
  }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  } catch {
    return false;
  }
}

/** 触发浏览器下载文本文件 */
export function downloadText(filename: string, text: string): void {
  const blob = new Blob([text], { type: 'text/yaml;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
