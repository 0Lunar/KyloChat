from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text
from rich.align import Align
from datetime import datetime
from core import SocketHandler
from core import Login
from core import MessageTypes
import time
import re
import threading
import os
import queue


console = Console()


class KyloChat:
    def __init__(self):
        self.messages = []
        self.username = None
        self.running = False
        self.receive_thread = None
        self.lock = threading.Lock()
        self.needs_refresh = False
        self.queue = queue.Queue()
        
    
    def show_login_screen(self) -> None:
        console.clear()
        
        header = Text()
        header.append("╔═══════════════════════════════════════╗\n", style="bold magenta")
        header.append("║                                       ║\n", style="bold magenta")
        header.append("║            ", style="bold magenta")
        header.append("KYLOCHAT", style="bold cyan")
        header.append("                   ║\n", style="bold magenta")
        header.append("║                                       ║\n", style="bold magenta")
        header.append("╚═══════════════════════════════════════╝", style="bold magenta")
        
        console.print(Align.center(header))
        console.print()
        
        login_panel = Panel(
            "[bold white]Please authenticate to continue[/bold white]\n\n"
            "[dim]Enter your credentials below[/dim]",
            title="🔐 Authentication Required",
            border_style="magenta",
            padding=(1, 2)
        )
        console.print(Align.center(login_panel))
        console.print()
        
    
    def validate_ip(self, ip) -> bool:
        """Validate IP address format"""
        return bool(re.match(r'^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$', ip))
    
    
    def validate_port(self, port) -> bool:
        """Validate port number"""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except ValueError:
            return False
    
    
    def get_server_connection(self) -> tuple[str, int]:
        """Returns server IP and port from user input"""
        while True:
            console.clear()
            
            header = Text()
            header.append("╔═══════════════════════════════════════╗\n", style="bold magenta")
            header.append("║                                       ║\n", style="bold magenta")
            header.append("║            ", style="bold magenta")
            header.append("KYLOCHAT", style="bold cyan")
            header.append("                   ║\n", style="bold magenta")
            header.append("║                                       ║\n", style="bold magenta")
            header.append("╚═══════════════════════════════════════╝", style="bold magenta")
            
            console.print(Align.center(header))
            console.print()
            
            connection_panel = Panel(
                "[bold white]Server Connection[/bold white]\n\n"
                "[dim]Enter server details to connect[/dim]",
                title="🌐 Connect to Server",
                border_style="magenta",
                padding=(1, 2)
            )
            console.print(Align.center(connection_panel))
            console.print()
            
            ip = Prompt.ask("\n[bold cyan]Server IP[/bold cyan]", default="127.0.0.1")
            
            if not self.validate_ip(ip):
                console.print("[bold red]✗ Invalid IP address![/bold red]")
                console.print("[yellow]IP must be in format: 0-255.0-255.0-255.0-255[/yellow]")
                time.sleep(1)
                continue
            
            port = Prompt.ask("[bold cyan]Port[/bold cyan]", default="5000")
            
            if not self.validate_port(port):
                console.print("[bold red]✗ Invalid port number![/bold red]")
                console.print("[yellow]Port must be between 1 and 65535[/yellow]")
                time.sleep(1)
                continue
            
            return (ip, int(port))
    
    
    def get_login_credentials(self) -> tuple[str, str]:
        """Returns username and password from user input"""        
        self.show_login_screen()
        
        username = Prompt.ask("\n[bold cyan]Username[/bold cyan]")
        password = Prompt.ask("[bold cyan]Password[/bold cyan]", password=True)
        
        return (username, password)
    
    
    def show_login_success(self, username) -> None:
        """Display success message after login"""
        console.print("\n[bold green]✓ Authentication successful![/bold green]")
        console.print(f"[dim]Welcome back, {username}![/dim]")
        time.sleep(1)
        self.username = username
    
    
    def show_login_failed(self, error_message="Invalid credentials") -> None:
        """Display error message after failed login"""
        console.print(f"\n[bold red]✗ Authentication failed![/bold red]")
        console.print(f"[yellow]{error_message}[/yellow]")
        time.sleep(2)
    
    
    def show_connecting(self) -> None:
        """Display connecting to server message"""
        console.print("\n[dim]Connecting to server...[/dim]")
        console.print("\n[yellow]Press CTRL+C to abort[/yellow]")
    
    
    def add_message(self, user, message, is_system=False) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        with self.lock:
            self.messages.append({
                'user': user,
                'message': message,
                'time': timestamp,
                'is_system': is_system
            })
            self.needs_refresh = True
    
    
    def render_chat(self) -> Panel:
        with self.lock:
            messages_to_render = self.messages[-15:]
        
        chat_content = ""
        for msg in messages_to_render:
            if msg['is_system']:
                chat_content += f"[dim italic]*** {msg['message']} ***[/dim italic]\n"
            else:
                color = "cyan" if msg['user'] == self.username else "green"
                chat_content += f"[{color}]{msg['user']}[/{color}] [{msg['time']}]: {msg['message']}\n"
        
        return Panel(
            chat_content.strip() if chat_content else "[dim]No messages yet...[/dim]",
            title="💬 KyloChat Room",
            border_style="magenta",
            padding=(1, 2)
        )
    
    
    def show_chat_header(self) -> Panel:
        header = Panel(
            f"[bold magenta]KyloChat[/bold magenta] | "
            f"[bold cyan]User: {self.username}[/bold cyan] | "
            f"[dim]Type '/exit' to leave[/dim]",
            border_style="magenta"
        )
        return header
    
    
    def clear_screen(self) -> None:
        """Clear screen in a cross-platform way"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    
    def display_chat(self) -> None:
        """Display the complete chat interface"""
        self.clear_screen()
        console.print(self.show_chat_header())
        console.print(self.render_chat())
        console.print()
    
    
    def get_user_message(self) -> str:
        """Get message input from user"""
        return Prompt.ask(f"[bold cyan]{self.username}[/bold cyan]")
    
    
    def start_chat(self) -> None:
        self.add_message("System", f"{self.username} joined the chat! 👋", is_system=True)
        self.display_chat()
    
    
    def handle_exit(self) -> None:
        """Handle user exit"""
        self.running = False
        self.add_message("System", f"{self.username} left the chat. 👋", is_system=True)
        self.clear_screen()
        console.print(self.show_chat_header())
        console.print(self.render_chat())
        console.print("\n[bold green]Goodbye! See you soon![/bold green]\n")
    
    
    def auto_refresh_thread(self) -> None:
        """Thread to automatically refresh display when new messages arrive"""
        last_message_count = 0
                
        while self.running:
            try:
                with self.lock:
                    current_count = len(self.messages)
                    needs_refresh = self.needs_refresh
                    self.needs_refresh = False
                
                if needs_refresh and current_count != last_message_count:
                    self.display_chat()
                    last_message_count = current_count
                
                time.sleep(0.5)
                
            except Exception:
                pass
    
    
    def receive_messages_thread(self, conn: SocketHandler, token: str) -> None:
        """Thread to receive messages from the server"""
        
        while self.running:
            try:
                if not self.running:
                    break
                
                type = int.from_bytes(conn.unsafe_recv(1), 'little')
                
                if type == MessageTypes.MESSAGE.value:
                    user = conn.recv_short_bytes().decode('utf-8', 'replace')

                    if not self.running:
                        break
                    
                    data = conn.recv_int_bytes().decode('utf-8', 'replace')

                    if data and user:
                        self.receive_message(user, data)

                    time.sleep(0.1)
                
                elif type == MessageTypes.STATUS_CODE.value:
                    code = int.from_bytes(conn.unsafe_recv(2), 'little')
                    self.queue.put(code)
                    
                
            except Exception as e:
                if self.running:
                    self.show_system_message(f"Connection error: {e}")
                break
    
    
    def isError(self, status_code: int) -> bool:
        return status_code in {400, 401, 403, 500}
    
    
    def handle_server_error(self, status_code: int, error_message: str | None = None) -> None:
        """Handle server error status codes"""
        error_messages = {
            400: "Bad Request - Invalid message format",
            401: "Unauthorized - expired token",
            403: "Forbidden - You don't have permission",
            500: "Internal Server Error - Try again later",
        }
        
        message = error_message if error_message else error_messages.get(status_code, f"Unknown error (Code: {status_code})")
        
        self.show_system_message(f"Error: {message}")
        
        if status_code in {401, 403}:
            console.print(f"\n[bold red]Session expired or unauthorized. Please login again.[/bold red]")
            time.sleep(2)
            self.running = False
    
    
    def send_message(self, conn: SocketHandler, token: str, message: str) -> bool:
        """Send a message to the server"""
        try:
            conn.send_int_bytes(token.encode('utf-8') + message.encode('utf-8'))
            
            if message == "/exit":
                return True
                        
            code = self.queue.get()
                
            if self.isError(code):
                self.handle_server_error(code)

            elif code not in {100, 200}:
                print(code)
                time.sleep(10)
                raise RuntimeError("Unexpected error")
            
            return True
        except Exception as e:
            self.show_system_message(f"Failed to send message: {e}")
            return False
    
    
    def run_chat_loop(self, conn: SocketHandler, token: str) -> None:
        """Main chat loop"""
        self.running = True
        self.start_chat()
        
        self.receive_thread = threading.Thread(
            target=self.receive_messages_thread,
            args=(conn, token),
            daemon=True
        )
        self.receive_thread.start()
        
        self.refresh_thread = threading.Thread(
            target=self.auto_refresh_thread,
            daemon=True
        )
        self.refresh_thread.start()
        
        while self.running:
            try:
                message = self.get_user_message()
                
                if message == '/exit':
                    self.send_message(conn, token, message)
                    self.handle_exit()
                    break
                
                if message.strip():
                    if self.send_message(conn, token, message):
                        self.add_message(self.username, message)
                
            except KeyboardInterrupt:
                console.print("\n\n[yellow]Chat interrupted.[/yellow]")
                self.running = False
                self.send_message(conn, token, '/exit')
                self.handle_exit()
                break
        
            except Exception as ex:
                console.print(f"\n\n[yellow]Warning: {ex}[/yellow]")
        
        if self.receive_thread and self.receive_thread.is_alive():
            self.receive_thread.join(timeout=2)
    
    
    def receive_message(self, username: str, message: str) -> None:
        """Call this method when receiving a message from server"""
        self.add_message(username, message)
    
    
    def show_system_message(self, message: str) -> None:
        """Display a system message"""
        self.add_message("System", message, is_system=True)


if __name__ == "__main__":
    chat = KyloChat()
    conn = SocketHandler()
        
    try:
        # Get Server info
        ip, port = chat.get_server_connection()

        # Get credentials
        username, password = chat.get_login_credentials()

        chat.show_connecting()

        conn.connect((ip, port))
        login = Login(conn)

        token = login.login(username, password)
    
        if token:
            chat.show_login_success(username)
            chat.run_chat_loop(conn, token)
        else:
            chat.show_login_failed("Invalid username or password")
    except ConnectionRefusedError:
        chat.show_login_failed('Server not available')
    except TimeoutError:
        chat.show_login_failed('Connection timeout')
    except OSError as e:
        chat.show_login_failed(f'Connection error: {e}')
    except RuntimeError as e:
        chat.show_login_failed(f'Connection failed: {e}')
    except KeyboardInterrupt:
        console.print("\n[yellow]Connection aborted[/yellow]")
