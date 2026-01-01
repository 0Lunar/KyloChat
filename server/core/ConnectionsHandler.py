from core.HandleConnection import SocketHandler
from dataclasses import dataclass
from typing import Optional
import threading


@dataclass
class ClientInfo:
    """Represents a connected client"""
    conn: SocketHandler
    addr: tuple[str, int]
    username: str
    session_id: str
    
    @property
    def host(self) -> str:
        return self.addr[0]
    
    @property
    def port(self) -> int:
        return self.addr[1]


class ConnHandler:
    """Thread-safe connection handler for managing multiple client connections"""
    
    def __init__(self) -> None:
        # Primary index: session_id -> ClientInfo
        self._sessions: dict[str, ClientInfo] = {}
        
        # Secondary indexes for fast lookups
        self._by_username: dict[str, str] = {}  # username -> session_id
        self._by_host: dict[str, str] = {}      # host -> session_id
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Session ID counter
        self._session_counter = 0
    
    
    def _generate_session_id(self) -> str:
        """Generate a unique session ID"""
        with self._lock:
            self._session_counter += 1
            return f"session_{self._session_counter}"
    
    
    def add(self, conn: SocketHandler, addr: tuple[str, int], username: str) -> str:
        """
        Add a new connection
        
        Args:
            conn: Socket connection handler
            addr: Client address (host, port)
            username: Client username
            
        Returns:
            session_id: Unique session identifier
            
        Raises:
            ValueError: If username already exists
        """
        with self._lock:
            # Check for duplicate username
            if username in self._by_username:
                raise ValueError(f"Username '{username}' already connected")
            
            # Generate unique session ID
            session_id = self._generate_session_id()
            
            # Create client info
            client = ClientInfo(conn, addr, username, session_id)
            
            # Store in primary index
            self._sessions[session_id] = client
            
            # Update secondary indexes
            self._by_username[username] = session_id
            self._by_host[client.host] = session_id
            
            return session_id
    
    
    def remove(self, session_id: str) -> Optional[ClientInfo]:
        """
        Remove a connection by session ID
        
        Args:
            session_id: Session identifier to remove
            
        Returns:
            ClientInfo if found, None otherwise
        """
        with self._lock:
            client = self._sessions.pop(session_id, None)
            
            if client:
                # Clean up secondary indexes
                self._by_username.pop(client.username, None)
                self._by_host.pop(client.host, None)
            
            return client
    
    
    def remove_by_username(self, username: str) -> Optional[ClientInfo]:
        """Remove a connection by username"""
        with self._lock:
            session_id = self._by_username.get(username)
            if session_id:
                return self.remove(session_id)
            return None
    
    
    def remove_by_host(self, host: str) -> Optional[ClientInfo]:
        """Remove a connection by host IP"""
        with self._lock:
            session_id = self._by_host.get(host)
            if session_id:
                return self.remove(session_id)
            return None
    
    
    def get(self, session_id: str) -> Optional[ClientInfo]:
        """Get client info by session ID"""
        with self._lock:
            return self._sessions.get(session_id)
    
    
    def get_by_username(self, username: str) -> Optional[ClientInfo]:
        """Get client info by username"""
        with self._lock:
            session_id = self._by_username.get(username)
            if session_id:
                return self._sessions.get(session_id)
            return None
    
    
    def get_by_host(self, host: str) -> Optional[ClientInfo]:
        """Get client info by host IP"""
        with self._lock:
            session_id = self._by_host.get(host)
            if session_id:
                return self._sessions.get(session_id)
            return None
    
    
    def get_conn(self, session_id: str) -> Optional[SocketHandler]:
        """Get connection handler by session ID"""
        client = self.get(session_id)
        return client.conn if client else None
    
    
    def get_conn_by_username(self, username: str) -> Optional[SocketHandler]:
        """Get connection handler by username"""
        client = self.get_by_username(username)
        return client.conn if client else None
    
    
    def exists(self, session_id: str) -> bool:
        """Check if a session exists"""
        with self._lock:
            return session_id in self._sessions
    
    
    def username_exists(self, username: str) -> bool:
        """Check if a username is connected"""
        with self._lock:
            return username in self._by_username
    
    
    def get_all_sessions(self) -> dict[str, ClientInfo]:
        """Get a copy of all sessions"""
        with self._lock:
            return self._sessions.copy()
    
    
    def get_all_conns(self) -> list[SocketHandler]:
        """Get all connection handlers"""
        with self._lock:
            return [client.conn for client in self._sessions.values()]
    
    
    def get_all_usernames(self) -> list[str]:
        """Get all connected usernames"""
        with self._lock:
            return list(self._by_username.keys())
    
    
    def get_all_hosts(self) -> list[str]:
        """Get all connected host IPs"""
        with self._lock:
            return list(self._by_host.keys())
    
    
    def count(self) -> int:
        """Get total number of connections"""
        with self._lock:
            return len(self._sessions)
    
    
    def broadcast(self, message: bytes, exclude_sessions: set[str] = None) -> int:
        """
        Broadcast a message to all connections
        
        Args:
            message: Message to send
            exclude_sessions: Set of session IDs to exclude
            
        Returns:
            Number of successful sends
        """
        exclude_sessions = exclude_sessions or set()
        success_count = 0
        
        with self._lock:
            clients = list(self._sessions.values())
        
        for client in clients:
            if client.session_id not in exclude_sessions:
                try:
                    client.conn.send(message)
                    success_count += 1
                except Exception:
                    pass  # Handle send failures silently
        
        return success_count
    
    
    def clear(self) -> None:
        """Remove all connections"""
        with self._lock:
            self._sessions.clear()
            self._by_username.clear()
            self._by_host.clear()
    
    
    def __len__(self) -> int:
        """Return number of active connections"""
        return self.count()
    
    
    def __contains__(self, session_id: str) -> bool:
        """Check if session_id exists"""
        return self.exists(session_id)
    
    
    def __repr__(self) -> str:
        return f"ConnHandler(connections={self.count()})"


# Example usage:
if __name__ == "__main__":
    handler = ConnHandler()
    
    # Simulate adding connections
    # session1 = handler.add(conn1, ("192.168.1.100", 5000), "alice")
    # session2 = handler.add(conn2, ("192.168.1.101", 5001), "bob")
    
    # Get by username
    # client = handler.get_by_username("alice")
    # print(f"Alice's session: {client.session_id}")
    
    # Broadcast to all except one
    # handler.broadcast(b"Hello everyone!", exclude_sessions={session1})
    
    # Remove by username
    # handler.remove_by_username("alice")
    
    print(handler)