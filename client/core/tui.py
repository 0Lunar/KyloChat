from textual.app import App, ComposeResult
from textual.containers import Container, Vertical, Horizontal, VerticalScroll
from textual.widgets import Header, Footer, Static, Input, RichLog, OptionList, Button
from textual.binding import Binding
from textual.screen import Screen, ModalScreen
from textual_fspicker.path_filters import Filters as FileFilters
from textual_fspicker import FileOpen
from textual_image.widget import Image as TerminalImage
from PIL import Image
from rich.text import Text
from datetime import datetime
from core import SocketHandler, Login, MessageTypes, Compressor
import threading
import queue
import re
import os
import io

class ConnectionScreen(Screen):
    """Screen for server connection input"""
    
    CSS = """
        ConnectionScreen {
        align: center middle;
    }
    
    #connection_box {
        width: 60;
        height: 16;
        border: thick $primary;
        padding: 1 2;
    }
    
    .input_label {
        margin-top: 1;
        color: $accent;
    }
    
    Input {
        margin-bottom: 1;
    }
    
    #error_msg {
        color: $error;
        margin-top: 1;
    }
    """
    
    BINDINGS = [
        Binding("escape", "app.quit", "Quit", show=True),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="connection_box"):
            yield Static("🌐 [bold magenta]KyloChat[/bold magenta] - Server Connection\n", id="title")
            yield Static("Server IP:", classes="input_label")
            yield Input(placeholder="127.0.0.1", value="127.0.0.1", id="ip_input")
            yield Static("Port:", classes="input_label")
            yield Input(placeholder="5000", value="5000", id="port_input")
        yield Footer()
    
    def validate_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        
        if ip.count('.') == 3 and not any([not i.isdigit() for i in ip.split('.')]):
            return bool(re.match(r'^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$', ip))
        
        if ip.split('.')[-1].isdigit():
            return False
        
        return bool(re.match(r'^((([A-Za-z0-9\-\_])+\.)+)?([A-Za-z0-9\-\_])+\.([A-Za-z0-9\-\_])+$', ip))
    
    def validate_port(self, port: str) -> bool:
        """Validate port number"""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except ValueError:
            return False
    
    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle input submission"""
        ip_input = self.query_one("#ip_input", Input)
        port_input = self.query_one("#port_input", Input)
        
        ip = ip_input.value
        port = port_input.value
        
        # Validate
        if not self.validate_ip(ip):
            self.notify("❌ Invalid IP address format", severity='error')
            return
        
        if not self.validate_port(port):
            self.notify("❌ Invalid port (1-65535)", severity='error')
            return
        
        ip_input.disabled = True
        port_input.disabled = True
        
        try:
            conn = SocketHandler()
            conn.connect((ip, int(port)))
        
            ip_input.disabled = False
            port_input.disabled = False
            
            login = Login(conn)
            if (token := login.checkCache()) == False:
                # Switch to login screen
                self.app.push_screen(LoginScreen(conn))
            
            else:
                tk = login.loging_cache()
                
                if tk:
                    username, token = tk
                    self.app.push_screen(ChatScreen(conn, token, username))
                
                else:
                    self.app.push_screen(LoginScreen(conn))
            
        except Exception as ex:
            ip_input.disabled = False
            port_input.disabled = False
            self.notify(f"❌ Connection failed: {ex}", severity='error')


class LoginScreen(Screen):
    """Screen for user authentication"""
    
    CSS = """
    LoginScreen {
        align: center middle;
    }
    
    #login_box {
        width: 60;
        height: 19;
        border: thick $primary;
        padding: 1 2;
    }
    
    .input_label {
        margin-top: 1;
        color: $accent;
    }
    
    Input {
        margin-bottom: 1;
    }
    
    #status_msg {
        margin-top: 1;
    }
    """
    
    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]
    
    def __init__(self, conn: SocketHandler):
        super().__init__()
        self.conn = conn
    
    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="login_box"):
            yield Static("🔐 [bold magenta]KyloChat[/bold magenta] - Login\n", id="title")
            yield Static(f"Server: {self.conn.addr[0]}:{self.conn.addr[1]}", id="server_info")
            yield Static("Username:", classes="input_label")
            yield Input(placeholder="Enter username", id="username_input")
            yield Static("Password:", classes="input_label")
            yield Input(placeholder="Enter password", password=True, id="password_input")
            yield Static("", id="status_msg")
        yield Footer()
    
    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle login submission"""
        username_input = self.query_one("#username_input", Input)
        password_input = self.query_one("#password_input", Input)
        status_msg = self.query_one("#status_msg", Static)
        
        username = username_input.value.strip()
        password = password_input.value.strip()
        
        if not username or not password:
            self.notify("[yellow]⚠ Please fill all fields[/yellow]", severity='warning')
            return
        
        # Disable inputs during connection
        username_input.disabled = True
        password_input.disabled = True
        status_msg.update("[cyan]🔄 Connecting to server...[/cyan]")
        
        # Connect in background thread
        def connect():
            try:
                self.app.call_from_thread(status_msg.update, "[cyan]🔄 Authenticating...[/cyan]")
                
                login = Login(self.conn)
                
                token = None
                try:
                    token = login.login(username, password)
                except TimeoutError:
                    raise TimeoutError("Authentication timeout - server not responding")
                
                if token:
                    login.saveToken(username, token)
                    self.app.call_from_thread(self.on_login_success, token, username)
                else:
                    self.app.call_from_thread(self.on_login_failed, "Invalid username or password")
                    
            except ConnectionRefusedError:
                if self.conn:
                    try:
                        self.conn.close()
                    except:
                        pass
                self.app.call_from_thread(self.on_login_failed, "Server not available")
            except TimeoutError as e:
                if self.conn:
                    try:
                        self.conn.close()
                    except:
                        pass
                self.app.call_from_thread(self.on_login_failed, f"Timeout: {str(e)}")
            
            except OSError:
                if self.conn:
                    try:
                        self.conn.close()
                    except:
                        pass
                
                self.app.call_from_thread(self.on_login_failed, "Connection closed - Too many failed attempts", True)
                
            except Exception as e:
                if self.conn:
                    try:
                        self.conn.close()
                    except:
                        pass
                self.app.call_from_thread(self.on_login_failed, f"Error: {str(e)}")
        
        threading.Thread(target=connect, daemon=True).start()
    
    def on_login_success(self, token: str, username: str):
        """Called when login succeeds"""
        self.app.push_screen(ChatScreen(self.conn, token, username))
    
    def on_login_failed(self, error: str, perm: bool = False):
        """Called when login fails"""
        self.notify(f"[red]❌ {error}[/red]", severity='error')
        
        username_input = self.query_one("#username_input", Input)
        password_input = self.query_one("#password_input", Input)
        
        if not perm:
            username_input.disabled = False
            password_input.disabled = False
    
    def action_back(self):
        """Go back to connection screen"""
        self.app.pop_screen()



class MenuScreen(ModalScreen):
    CSS = """
    MenuScreen {
        background: rgba(0, 0, 0, 0.6);
    }
    """
    
    BINDINGS = [
        Binding("escape", "abort_key", "Back", show=True),
    ]
    
    def __init__(self, compression: bool = False) -> None:
        super().__init__()
        self.compression = compression
    
    def compose(self) -> ComposeResult:
        yield OptionList(
            "Clear chat",
            "Enable compression" if not self.compression else "Disable compression",
            "Send image",
            "Exit chat",
            "Logout",
            "Abort"
        )
        
    def action_abort_key(self):
        self.dismiss("Abort")
        
    def on_option_list_option_selected(self, event):
        self.dismiss(event.option.prompt)


class ChatScreen(Screen):
    """Main chat screen"""
    
    CSS = """
    ChatScreen {
        layout: vertical;
    }
    
    #chat_container {
        height: 1fr;
        border: solid $primary;
        padding: 0 1;
    }
    
    #message_log {
        height: 1fr;
        background: $surface;
    }
    
    #img_widget {
        width: 0.4fr;
    }
    
    #input_container {
        layout: horizontal;
        height: auto;
        padding: 1;
        background: $panel;
    }
    
    #menu_btn {
        width: 3%
    }
    
    #message_input {
        width: 90%;
    }
    
    .user_image {
        text-align: center;
        padding: 1 1;
        margin: 1 1;

        background: $panel;
        color: $text;
    }
    
    .img_center {
        content-align: center middle;
        height: 15;
    }
    """
    
    BINDINGS = [
        Binding("ctrl+q", "quit_chat", "Quit", show=True),
    ]
    
    def __init__(self, conn: SocketHandler, token: str, username: str):
        super().__init__()
        self.conn = conn
        self.token = token
        self.username = username
        self.running = False
        self.compression = False
        self.queue = queue.Queue()
    
    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="chat_container"):
            yield RichLog(id="message_log", wrap=True, highlight=True, markup=True)
            yield VerticalScroll(id='img_widget')
        with Container(id="input_container"):
            yield Button(label="▶", id='menu_btn')
            yield Input(placeholder="Type your message...", id="message_input")

        yield Footer()
    
    def on_mount(self) -> None:
        """Called when screen is mounted"""
        # Update header
        self.app.title = f"KyloChat - {self.username}"
        
        # Add welcome message
        message_log = self.query_one("#message_log", RichLog)
        message_log.write(Text("*** Welcome to KyloChat! ***", style="bold magenta"))
        message_log.write(Text(f"*** {self.username} joined the chat! 👋 ***", style="italic yellow"))
        
        # Start receive thread
        self.running = True
        self.receive_thread = threading.Thread(
            target=self.receive_messages_thread,
            daemon=True
        )
        self.receive_thread.start()
        
        # Focus input
        self.query_one("#message_input", Input).focus()
    
    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle message send"""
        message_input = self.query_one("#message_input", Input)
        message = message_input.value.strip()
        
        if not message:
            return
        
        # Clear input
        message_input.value = ""
        
        # Handle exit
        if message == "/exit":
            self.action_quit_chat()
            return
        
        # Send message
        if self.send_message(message):
            self.add_message(self.username, message, is_own=True)
    
    def on_button_pressed(self, event):
        if event.button.id == 'menu_btn':
            self.app.push_screen(MenuScreen(self.compression), self.on_menu_closed)
            
            
    def on_menu_closed(self, result: str | None):        
        if result == "Clear chat":
            self.query_one("#message_log", RichLog).clear()
            self.query_one("#img_widget", VerticalScroll).remove_children()
            
            
        elif result == "Enable compression":
            self.compression = True
          
        elif result == "Disable compression":
            self.compression = False
            
        elif result == "Send image":
            self.run_worker(self.select_image)
            
        elif result == "Exit chat":
            self.action_quit_chat()
            
        elif result == "Logout":
            login = Login(self.conn)
            login.removeToken()
            self.action_quit_chat()
            

    async def select_image(self) -> None:
        fspicker = FileOpen(title='Select an image', 
                            must_exist=True, 
                            filters=FileFilters(
                                ("PNG", lambda p: p.suffix.lower() == '.png'),
                                ("JPEG", lambda p: p.suffix.lower() == '.jpeg'),
                                ("JPG", lambda p: p.suffix.lower() == '.jpg'),
                                ("WEBP", lambda p: p.suffix.lower() == '.webp'),
                            )
                    )
        file = str(await self.app.push_screen_wait(fspicker))
        
        if not os.path.isfile(file):
            self.notify("Invalid file", severity='error')
            return
    
        try:
            with open(file, 'rb') as f:
                img = Image.open(f)

                width = img.width
                height = img.height

                while width >= 600 or height >= 400:
                    width //= 1.2
                    height //= 1.2


                img = img.resize([int(width), int(height)])
                
                image_data = io.BytesIO()
                img.save(image_data, format='PNG')
                image_data = image_data.getvalue()
                img.close()
            
            if self.compression:
                compressor = Compressor()
                compressed_image_data = compressor.compress(image_data) + compressor.flush()
                self.conn.unsafe_send(MessageTypes.COMPRESSED_IMAGE.value.to_bytes(1, 'little'))
                self.conn.send_int_bytes(self.token.encode(encoding='utf-8', errors='strict') + compressed_image_data)
            else:
                self.conn.unsafe_send(MessageTypes.IMAGE.value.to_bytes(1, 'little'))
                self.conn.send_int_bytes(self.token.encode(encoding='utf-8', errors='strict') + image_data)
                
            code = self.queue.get(timeout=5)
            
            if code in {400, 401, 403, 500}:
                self.handle_server_error(code)
                self.notify("Error sending the image", severity='error')
            else:
                self.add_image(self.username, image_data)
                self.notify("Image sent successfully")
        except Exception as ex:
            self.notify(f"Error opening the image: {ex}", severity='error')
        # TODO INVIO DEL FILE
        
    
    def add_message(self, username: str, message, is_own: bool = False, is_system: bool = False):
        """Add message to chat log"""
        message_log = self.query_one("#message_log", RichLog)
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if is_system:
            text = Text(f"*** {message} ***", style="italic yellow")
        else:
            style = "bold cyan" if is_own else "bold green"
            text = Text()
            text.append(username, style=style)
            text.append(f" [{timestamp}]: ", style="dim")
            text.append(message)
        
        message_log.write(text)
        
    def add_image(self, username: str, image: bytes | Image.Image) -> None:
        if type(image) == bytes:
            image = Image.open(io.BytesIO(image))
        
        image_list = self.query_one("#img_widget", VerticalScroll)
                
        image_list.mount(
            Static(
                username,
                classes="user_image"
            )
        )
        
        image_list.mount(
            TerminalImage(
                image,
                classes="img_center"
            )
        )
        
        image_list.scroll_end(animate=True)
        
    
    def send_message(self, message: str) -> bool:
        """Send message to server"""
        try:
            if self.compression:
                self.conn.unsafe_send(MessageTypes.COMPRESSED_MSG.value.to_bytes(1, 'little'))
                payload = self.token.encode(encoding='utf-8', errors='strict') + message.encode(encoding='utf-8', errors='strict')
                compressor = Compressor()
                payload = compressor.compress(payload) + compressor.flush()
                
                self.conn.send_int_bytes(payload)
            else:
                self.conn.unsafe_send(MessageTypes.MESSAGE.value.to_bytes(1, 'little'))
                self.conn.send_int_bytes(self.token.encode(encoding='utf-8', errors='strict') + message.encode(encoding='utf-8', errors='srict'))
            
            # Wait for status code
            code = self.queue.get(timeout=5)
            
            if code in {400, 401, 403, 500}:
                self.handle_server_error(code)
                return False
            
            return code in {100, 200}
        
        except queue.Empty:
            self.notify("Server response timeout", severity='error')
            return False
        except Exception as e:
            self.notify(f"Failed to send: {e}", severity='error')
            return False
    
    def handle_server_error(self, code: int):
        """Handle server error codes"""
        errors = {
            400: "Bad Request - Invalid message format",
            401: "Unauthorized",
            403: "Forbidden - No permission",
            500: "Internal Server Error"
        }
        self.notify(f"Error: {errors.get(code, f'Unknown error ({code})')}", severity='error')
            
    def receive_messages_thread(self):
        """Thread to receive messages from server"""
        while self.running:
            try:
                msg_type = int.from_bytes(self.conn.unsafe_recv(1), 'little')
                                
                if msg_type == MessageTypes.MESSAGE.value:
                    user = self.conn.recv_short_bytes().decode('utf-8', 'replace')
                    data = self.conn.recv_int_bytes().decode('utf-8', 'replace')
                    
                    if user and data:
                        self.app.call_from_thread(self.add_message, user, data, is_own=False)
                
                elif msg_type == MessageTypes.STATUS_CODE.value:
                    code = int.from_bytes(self.conn.unsafe_recv(2), 'little')
                    self.queue.put(code)
                    
                elif msg_type == MessageTypes.IMAGE.value:
                    user = self.conn.recv_short_bytes().decode('utf-8', 'replace')
                    data = self.conn.recv_int_bytes()

                    if user and data:
                        self.app.call_from_thread(self.add_image, user, data)
            
            except Exception as e:
                if self.running:
                    self.app.notify(f"Connection error: {e}", severity='error')
                break
    
    def action_quit_chat(self):
        """Quit chat and return to connection screen"""
        try:
            self.conn.unsafe_send(MessageTypes.MESSAGE.value.to_bytes(1, 'little'))
            self.conn.send_int_bytes(self.token.encode(encoding='utf-8', errors='strict') + b'/exit')
            self.conn.close()
        except:
            pass
        
        self.running = False
        self.app.pop_screen()
        self.app.pop_screen()
        self.app.exit()


class KyloChatApp(App):
    """KyloChat Textual Application"""
    
    CSS = """
    Screen {
        background: $background;
    }
    """
    
    TITLE = "KyloChat"
    SUB_TITLE = "Versatile and secure chat"
    
    def on_mount(self) -> None:
        """Called when app starts"""
        self.push_screen(ConnectionScreen())