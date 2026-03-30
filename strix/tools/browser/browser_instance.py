import asyncio
import base64
import contextlib
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, cast

from playwright.async_api import Browser, BrowserContext, Page, Playwright, async_playwright


logger = logging.getLogger(__name__)

MAX_PAGE_SOURCE_LENGTH = 20_000
MAX_CONSOLE_LOG_LENGTH = 30_000
MAX_INDIVIDUAL_LOG_LENGTH = 1_000
MAX_CONSOLE_LOGS_COUNT = 200
MAX_JS_RESULT_LENGTH = 5_000
MAX_NETWORK_LOG_ENTRIES = 200
MAX_RESPONSE_BODY_LENGTH = 10_000


class _BrowserState:
    """Singleton state for the shared browser instance."""

    lock = threading.Lock()
    event_loop: asyncio.AbstractEventLoop | None = None
    event_loop_thread: threading.Thread | None = None
    playwright: Playwright | None = None
    browser: Browser | None = None


_state = _BrowserState()


def _ensure_event_loop() -> None:
    if _state.event_loop is not None:
        return

    def run_loop() -> None:
        _state.event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_state.event_loop)
        _state.event_loop.run_forever()

    _state.event_loop_thread = threading.Thread(target=run_loop, daemon=True)
    _state.event_loop_thread.start()

    while _state.event_loop is None:
        threading.Event().wait(0.01)


async def _create_browser() -> Browser:
    if _state.browser is not None and _state.browser.is_connected():
        return _state.browser

    if _state.browser is not None:
        with contextlib.suppress(Exception):
            await _state.browser.close()
        _state.browser = None
    if _state.playwright is not None:
        with contextlib.suppress(Exception):
            await _state.playwright.stop()
        _state.playwright = None

    _state.playwright = await async_playwright().start()
    _state.browser = await _state.playwright.chromium.launch(
        headless=True,
        args=[
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-web-security",
        ],
    )
    return _state.browser


def _get_browser() -> tuple[asyncio.AbstractEventLoop, Browser]:
    with _state.lock:
        _ensure_event_loop()
        assert _state.event_loop is not None

        if _state.browser is None or not _state.browser.is_connected():
            future = asyncio.run_coroutine_threadsafe(_create_browser(), _state.event_loop)
            future.result(timeout=30)

        assert _state.browser is not None
        return _state.event_loop, _state.browser


class BrowserInstance:
    def __init__(self) -> None:
        self.is_running = True
        self._execution_lock = threading.Lock()

        self._loop: asyncio.AbstractEventLoop | None = None
        self._browser: Browser | None = None

        self.context: BrowserContext | None = None
        self.pages: dict[str, Page] = {}
        self.current_page_id: str | None = None
        self._next_tab_id = 1

        self.console_logs: dict[str, list[dict[str, Any]]] = {}
        self.network_log: dict[str, list[dict[str, Any]]] = {}
        self._init_scripts: list[str] = []
        self._auth_cookies_injected = False

    def _run_async(self, coro: Any) -> dict[str, Any]:
        if not self._loop or not self.is_running:
            raise RuntimeError("Browser instance is not running")

        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return cast("dict[str, Any]", future.result(timeout=30))  # 30 second timeout

    async def _setup_console_logging(self, page: Page, tab_id: str) -> None:
        self.console_logs[tab_id] = []

        def handle_console(msg: Any) -> None:
            text = msg.text
            if len(text) > MAX_INDIVIDUAL_LOG_LENGTH:
                text = text[:MAX_INDIVIDUAL_LOG_LENGTH] + "... [TRUNCATED]"

            log_entry = {
                "type": msg.type,
                "text": text,
                "location": msg.location,
                "timestamp": asyncio.get_event_loop().time(),
            }

            self.console_logs[tab_id].append(log_entry)

            if len(self.console_logs[tab_id]) > MAX_CONSOLE_LOGS_COUNT:
                self.console_logs[tab_id] = self.console_logs[tab_id][-MAX_CONSOLE_LOGS_COUNT:]

        page.on("console", handle_console)

    async def _setup_network_capture(self, page: Page, tab_id: str) -> None:
        self.network_log[tab_id] = []

        def handle_request(request: Any) -> None:
            entry: dict[str, Any] = {
                "url": request.url,
                "method": request.method,
                "request_headers": dict(request.headers),
                "request_body": request.post_data,
                "status": None,
                "response_headers": {},
                "response_body": "",
                "timestamp": asyncio.get_event_loop().time(),
            }
            log = self.network_log.setdefault(tab_id, [])
            log.append(entry)
            if len(log) > MAX_NETWORK_LOG_ENTRIES:
                self.network_log[tab_id] = log[-MAX_NETWORK_LOG_ENTRIES:]

        async def handle_response(response: Any) -> None:
            log = self.network_log.get(tab_id, [])
            for entry in reversed(log):
                if entry.get("url") == response.url and entry.get("status") is None:
                    entry["status"] = response.status
                    entry["response_headers"] = dict(response.headers)
                    try:
                        body = await response.body()
                        body_str = body.decode("utf-8", errors="replace")
                        if len(body_str) > MAX_RESPONSE_BODY_LENGTH:
                            body_str = body_str[:MAX_RESPONSE_BODY_LENGTH] + "... [TRUNCATED]"
                        entry["response_body"] = body_str
                    except Exception:  # noqa: BLE001
                        entry["response_body"] = "[body unavailable]"
                    break

        page.on("request", handle_request)
        page.on("response", lambda r: asyncio.ensure_future(handle_response(r)))

    async def _create_context(self, url: str | None = None) -> dict[str, Any]:
        assert self._browser is not None

        # Read pre-configured auth headers from environment (set by docker_runtime)
        extra_http_headers: dict[str, str] = {}
        auth_headers_raw = os.environ.get("STRIX_AUTH_HEADERS_JSON", "")
        if auth_headers_raw:
            try:
                extra_http_headers = json.loads(auth_headers_raw)
            except (json.JSONDecodeError, ValueError):
                pass

        context_kwargs: dict[str, Any] = {
            "viewport": {"width": 1280, "height": 720},
            "user_agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            ),
        }
        if extra_http_headers:
            context_kwargs["extra_http_headers"] = extra_http_headers

        self.context = await self._browser.new_context(**context_kwargs)

        page = await self.context.new_page()
        tab_id = f"tab_{self._next_tab_id}"
        self._next_tab_id += 1
        self.pages[tab_id] = page
        self.current_page_id = tab_id

        await self._setup_console_logging(page, tab_id)
        await self._setup_network_capture(page, tab_id)

        if url:
            await page.goto(url, wait_until="domcontentloaded")

        return await self._get_page_state(tab_id)

    async def _get_page_state(self, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        page = self.pages[tab_id]

        await asyncio.sleep(2)

        screenshot_bytes = await page.screenshot(type="png", full_page=False)
        screenshot_b64 = base64.b64encode(screenshot_bytes).decode("utf-8")

        url = page.url
        title = await page.title()
        viewport = page.viewport_size

        all_tabs = {}
        for tid, tab_page in self.pages.items():
            all_tabs[tid] = {
                "url": tab_page.url,
                "title": await tab_page.title() if not tab_page.is_closed() else "Closed",
            }

        return {
            "screenshot": screenshot_b64,
            "url": url,
            "title": title,
            "viewport": viewport,
            "tab_id": tab_id,
            "all_tabs": all_tabs,
        }

    def launch(self, url: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            if self.context is not None:
                raise ValueError("Browser is already launched")

            self._loop, self._browser = _get_browser()
            return self._run_async(self._create_context(url))

    def goto(self, url: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._goto(url, tab_id))

    async def _inject_auth_cookies_if_needed(self, url: str) -> None:
        """Inject pre-configured auth cookies on first navigation, bound to the target origin."""
        if self._auth_cookies_injected or not self.context:
            return
        self._auth_cookies_injected = True
        auth_cookies_raw = os.environ.get("STRIX_AUTH_COOKIES_JSON", "")
        if not auth_cookies_raw:
            return
        try:
            cookies: list[dict[str, str]] = json.loads(auth_cookies_raw)
            for cookie in cookies:
                await self.context.add_cookies([{**cookie, "url": url}])
        except (json.JSONDecodeError, ValueError):
            pass

    async def _goto(self, url: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        await self._inject_auth_cookies_if_needed(url)

        page = self.pages[tab_id]
        await page.goto(url, wait_until="domcontentloaded")

        return await self._get_page_state(tab_id)

    def click(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._click(coordinate, tab_id))

    async def _click(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        try:
            x, y = map(int, coordinate.split(","))
        except ValueError as e:
            raise ValueError(f"Invalid coordinate format: {coordinate}. Use 'x,y'") from e

        page = self.pages[tab_id]
        await page.mouse.click(x, y)

        return await self._get_page_state(tab_id)

    def type_text(self, text: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._type_text(text, tab_id))

    async def _type_text(self, text: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        page = self.pages[tab_id]
        await page.keyboard.type(text)

        return await self._get_page_state(tab_id)

    def scroll(self, direction: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._scroll(direction, tab_id))

    async def _scroll(self, direction: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        page = self.pages[tab_id]

        if direction == "down":
            await page.keyboard.press("PageDown")
        elif direction == "up":
            await page.keyboard.press("PageUp")
        else:
            raise ValueError(f"Invalid scroll direction: {direction}")

        return await self._get_page_state(tab_id)

    def back(self, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._back(tab_id))

    async def _back(self, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        page = self.pages[tab_id]
        await page.go_back(wait_until="domcontentloaded")

        return await self._get_page_state(tab_id)

    def forward(self, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._forward(tab_id))

    async def _forward(self, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        page = self.pages[tab_id]
        await page.go_forward(wait_until="domcontentloaded")

        return await self._get_page_state(tab_id)

    def new_tab(self, url: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._new_tab(url))

    async def _new_tab(self, url: str | None = None) -> dict[str, Any]:
        if not self.context:
            raise ValueError("Browser not launched")

        page = await self.context.new_page()
        tab_id = f"tab_{self._next_tab_id}"
        self._next_tab_id += 1
        self.pages[tab_id] = page
        self.current_page_id = tab_id

        await self._setup_console_logging(page, tab_id)
        await self._setup_network_capture(page, tab_id)

        if url:
            await page.goto(url, wait_until="domcontentloaded")

        return await self._get_page_state(tab_id)

    def switch_tab(self, tab_id: str) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._switch_tab(tab_id))

    async def _switch_tab(self, tab_id: str) -> dict[str, Any]:
        if tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        self.current_page_id = tab_id
        return await self._get_page_state(tab_id)

    def close_tab(self, tab_id: str) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._close_tab(tab_id))

    async def _close_tab(self, tab_id: str) -> dict[str, Any]:
        if tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        if len(self.pages) == 1:
            raise ValueError("Cannot close the last tab")

        page = self.pages.pop(tab_id)
        await page.close()

        if tab_id in self.console_logs:
            del self.console_logs[tab_id]

        if tab_id in self.network_log:
            del self.network_log[tab_id]

        if self.current_page_id == tab_id:
            self.current_page_id = next(iter(self.pages.keys()))

        return await self._get_page_state(self.current_page_id)

    def wait(self, duration: float, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._wait(duration, tab_id))

    async def _wait(self, duration: float, tab_id: str | None = None) -> dict[str, Any]:
        await asyncio.sleep(duration)
        return await self._get_page_state(tab_id)

    def execute_js(self, js_code: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._execute_js(js_code, tab_id))

    async def _execute_js(self, js_code: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        page = self.pages[tab_id]

        try:
            result = await page.evaluate(js_code)
        except Exception as e:  # noqa: BLE001
            result = {
                "error": True,
                "error_type": type(e).__name__,
                "error_message": str(e),
            }

        result_str = str(result)
        if len(result_str) > MAX_JS_RESULT_LENGTH:
            result = result_str[:MAX_JS_RESULT_LENGTH] + "... [JS result truncated at 5k chars]"

        state = await self._get_page_state(tab_id)
        state["js_result"] = result
        return state

    def get_console_logs(self, tab_id: str | None = None, clear: bool = False) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._get_console_logs(tab_id, clear))

    async def _get_console_logs(
        self, tab_id: str | None = None, clear: bool = False
    ) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        logs = self.console_logs.get(tab_id, [])

        total_length = sum(len(str(log)) for log in logs)
        if total_length > MAX_CONSOLE_LOG_LENGTH:
            truncated_logs: list[dict[str, Any]] = []
            current_length = 0

            for log in reversed(logs):
                log_length = len(str(log))
                if current_length + log_length <= MAX_CONSOLE_LOG_LENGTH:
                    truncated_logs.insert(0, log)
                    current_length += log_length
                else:
                    break

            if len(truncated_logs) < len(logs):
                truncation_notice = {
                    "type": "info",
                    "text": (
                        f"[TRUNCATED: {len(logs) - len(truncated_logs)} older logs "
                        f"removed to stay within {MAX_CONSOLE_LOG_LENGTH} character limit]"
                    ),
                    "location": {},
                    "timestamp": 0,
                }
                truncated_logs.insert(0, truncation_notice)

            logs = truncated_logs

        if clear:
            self.console_logs[tab_id] = []

        state = await self._get_page_state(tab_id)
        state["console_logs"] = logs
        return state

    def view_source(self, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._view_source(tab_id))

    async def _view_source(self, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        page = self.pages[tab_id]
        source = await page.content()
        original_length = len(source)

        if original_length > MAX_PAGE_SOURCE_LENGTH:
            truncation_message = (
                f"\n\n<!-- [TRUNCATED: {original_length - MAX_PAGE_SOURCE_LENGTH} "
                "characters removed] -->\n\n"
            )
            available_space = MAX_PAGE_SOURCE_LENGTH - len(truncation_message)
            truncate_point = available_space // 2

            source = source[:truncate_point] + truncation_message + source[-truncate_point:]

        state = await self._get_page_state(tab_id)
        state["page_source"] = source
        return state

    def double_click(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._double_click(coordinate, tab_id))

    async def _double_click(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        try:
            x, y = map(int, coordinate.split(","))
        except ValueError as e:
            raise ValueError(f"Invalid coordinate format: {coordinate}. Use 'x,y'") from e

        page = self.pages[tab_id]
        await page.mouse.dblclick(x, y)

        return await self._get_page_state(tab_id)

    def hover(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._hover(coordinate, tab_id))

    async def _hover(self, coordinate: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        try:
            x, y = map(int, coordinate.split(","))
        except ValueError as e:
            raise ValueError(f"Invalid coordinate format: {coordinate}. Use 'x,y'") from e

        page = self.pages[tab_id]
        await page.mouse.move(x, y)

        return await self._get_page_state(tab_id)

    def press_key(self, key: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._press_key(key, tab_id))

    async def _press_key(self, key: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        page = self.pages[tab_id]
        await page.keyboard.press(key)

        return await self._get_page_state(tab_id)

    def save_pdf(self, file_path: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._save_pdf(file_path, tab_id))

    async def _save_pdf(self, file_path: str, tab_id: str | None = None) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        if not Path(file_path).is_absolute():
            file_path = str(Path("/workspace") / file_path)

        page = self.pages[tab_id]
        await page.pdf(path=file_path)

        state = await self._get_page_state(tab_id)
        state["pdf_saved"] = file_path
        return state

    def capture_network(self, tab_id: str | None = None, max_entries: int = 100) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._capture_network(tab_id, max_entries))

    async def _capture_network(
        self, tab_id: str | None = None, max_entries: int = 100
    ) -> dict[str, Any]:
        if not tab_id:
            tab_id = self.current_page_id

        if not tab_id or tab_id not in self.pages:
            raise ValueError(f"Tab '{tab_id}' not found")

        log = self.network_log.get(tab_id, [])
        entries = log[-max_entries:] if len(log) > max_entries else list(log)

        state = await self._get_page_state(tab_id)
        state["network_log"] = entries
        state["total_captured"] = len(log)
        return state

    def intercept_requests(self, url_pattern: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._intercept_requests(url_pattern, tab_id))

    async def _intercept_requests(
        self, url_pattern: str, tab_id: str | None = None
    ) -> dict[str, Any]:
        if not self.context:
            raise ValueError("Browser not launched")

        if not tab_id:
            tab_id = self.current_page_id

        log_tab_id = tab_id

        async def handle_route(route: Any, request: Any) -> None:
            entry: dict[str, Any] = {
                "url": request.url,
                "method": request.method,
                "request_headers": dict(request.headers),
                "request_body": request.post_data,
                "intercepted": True,
                "timestamp": asyncio.get_event_loop().time(),
            }
            log = self.network_log.setdefault(log_tab_id or "", [])
            log.append(entry)
            await route.continue_()

        await self.context.route(url_pattern, handle_route)

        state = await self._get_page_state(tab_id)
        state["message"] = f"Request interception enabled for pattern: {url_pattern}"
        return state

    def modify_request(
        self,
        url_pattern: str,
        headers: dict[str, str] | None = None,
        tab_id: str | None = None,
    ) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._modify_request(url_pattern, headers or {}, tab_id))

    async def _modify_request(
        self,
        url_pattern: str,
        headers: dict[str, str],
        tab_id: str | None = None,
    ) -> dict[str, Any]:
        if not self.context:
            raise ValueError("Browser not launched")

        if not tab_id:
            tab_id = self.current_page_id

        extra_headers = dict(headers)

        async def handle_route(route: Any, request: Any) -> None:
            merged_headers = {**request.headers, **extra_headers}
            await route.continue_(headers=merged_headers)

        await self.context.route(url_pattern, handle_route)

        state = await self._get_page_state(tab_id)
        state["message"] = (
            f"Request modification enabled for pattern: {url_pattern}. "
            f"Injected headers: {list(extra_headers.keys())}"
        )
        return state

    def inject_init_script(self, script: str, tab_id: str | None = None) -> dict[str, Any]:
        with self._execution_lock:
            return self._run_async(self._inject_init_script(script, tab_id))

    async def _inject_init_script(
        self, script: str, tab_id: str | None = None
    ) -> dict[str, Any]:
        if not self.context:
            raise ValueError("Browser not launched")

        if not tab_id:
            tab_id = self.current_page_id

        await self.context.add_init_script(script=script)
        self._init_scripts.append(script)

        state = await self._get_page_state(tab_id)
        state["message"] = (
            f"Init script injected. Total active init scripts: {len(self._init_scripts)}"
        )
        return state

    def close(self) -> None:
        with self._execution_lock:
            self.is_running = False
            if self._loop and self.context:
                future = asyncio.run_coroutine_threadsafe(self._close_context(), self._loop)
                with contextlib.suppress(Exception):
                    future.result(timeout=5)

            self.pages.clear()
            self.console_logs.clear()
            self.network_log.clear()
            self._init_scripts.clear()
            self.current_page_id = None
            self.context = None
            self._auth_cookies_injected = False

    async def _close_context(self) -> None:
        try:
            if self.context:
                await self.context.close()
        except (OSError, RuntimeError) as e:
            logger.warning(f"Error closing context: {e}")

    def is_alive(self) -> bool:
        return (
            self.is_running
            and self.context is not None
            and self._browser is not None
            and self._browser.is_connected()
        )
