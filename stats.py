#!/usr/bin/env python3
"""
Statistics tracking module for EasyUIVPN
Handles bandwidth monitoring, connection history, and data retention
"""

import json
import os
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import threading
import time

logger = logging.getLogger(__name__)

class StatsManager:
    def __init__(self, stats_file: str = '/var/lib/easyvpn/stats.json', retention_days: int = 7):
        self.stats_file = stats_file
        self.retention_days = retention_days
        self.stats_data = self._load_stats()
        self._stats_lock = threading.Lock()
        
        # Ensure the directory exists
        os.makedirs(os.path.dirname(stats_file), exist_ok=True)
        
    def _load_stats(self) -> Dict[str, Any]:
        """Load statistics from file"""
        try:
            if os.path.exists(self.stats_file):
                with open(self.stats_file, 'r') as f:
                    data = json.load(f)
                    return data
        except Exception as e:
            logger.error(f"Error loading stats file: {e}")
        
        # Return default structure
        return {
            'connections': {},  # client_name -> list of connection records
            'bandwidth': {},    # client_name -> bandwidth data
            'summary': {        # Overall statistics
                'total_connections': 0,
                'max_concurrent_connections': 0,
                'total_bandwidth_sent': 0,
                'total_bandwidth_received': 0,
                'first_connection': None,
                'last_connection': None
            }
        }
    
    def _save_stats(self):
        """Save statistics to file"""
        try:
            with self._stats_lock:
                # Clean old data before saving
                self._cleanup_old_data()
                
                with open(self.stats_file, 'w') as f:
                    json.dump(self.stats_data, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving stats file: {e}")
    
    def _cleanup_old_data(self):
        """Remove data older than retention period"""
        cutoff_date = datetime.now() - timedelta(days=self.retention_days)
        cutoff_timestamp = cutoff_date.isoformat()
        
        # Clean connection history
        for client_name in list(self.stats_data['connections'].keys()):
            connections = self.stats_data['connections'][client_name]
            # Keep only connections within retention period
            self.stats_data['connections'][client_name] = [
                conn for conn in connections 
                if conn.get('disconnect_time', conn.get('connect_time', '')) > cutoff_timestamp
            ]
            
            # Remove empty client records
            if not self.stats_data['connections'][client_name]:
                del self.stats_data['connections'][client_name]
        
        # Clean bandwidth data
        for client_name in list(self.stats_data['bandwidth'].keys()):
            if client_name not in self.stats_data['connections']:
                del self.stats_data['bandwidth'][client_name]
    
    def record_connection(self, client_name: str, client_ip: str, virtual_ip: str, 
                         bytes_sent: int = 0, bytes_received: int = 0):
        """Record a new connection or update existing connection"""
        now = datetime.now().isoformat()
        
        with self._stats_lock:
            # Initialize client data if not exists
            if client_name not in self.stats_data['connections']:
                self.stats_data['connections'][client_name] = []
            
            if client_name not in self.stats_data['bandwidth']:
                self.stats_data['bandwidth'][client_name] = {
                    'total_sent': 0,
                    'total_received': 0,
                    'sessions': []
                }
            
            # Check if there's an active connection (no disconnect_time)
            active_connection = None
            for conn in self.stats_data['connections'][client_name]:
                if 'disconnect_time' not in conn:
                    active_connection = conn
                    break
            
            if active_connection:
                # Update existing connection
                active_connection.update({
                    'bytes_sent': bytes_sent,
                    'bytes_received': bytes_received,
                    'last_seen': now
                })
            else:
                # Create new connection record
                connection_record = {
                    'connect_time': now,
                    'client_ip': client_ip,
                    'virtual_ip': virtual_ip,
                    'bytes_sent': bytes_sent,
                    'bytes_received': bytes_received,
                    'last_seen': now
                }
                
                self.stats_data['connections'][client_name].append(connection_record)
                
                # Update summary statistics
                self.stats_data['summary']['total_connections'] += 1
                if not self.stats_data['summary']['first_connection']:
                    self.stats_data['summary']['first_connection'] = now
                self.stats_data['summary']['last_connection'] = now
        
        self._save_stats()
    
    def record_disconnection(self, client_name: str):
        """Record client disconnection"""
        now = datetime.now().isoformat()
        
        with self._stats_lock:
            if client_name in self.stats_data['connections']:
                # Find and close active connection
                for conn in self.stats_data['connections'][client_name]:
                    if 'disconnect_time' not in conn:
                        conn['disconnect_time'] = now
                        
                        # Update bandwidth totals
                        if client_name in self.stats_data['bandwidth']:
                            self.stats_data['bandwidth'][client_name]['total_sent'] += conn.get('bytes_sent', 0)
                            self.stats_data['bandwidth'][client_name]['total_received'] += conn.get('bytes_received', 0)
                            
                            # Record session summary
                            session_data = {
                                'start': conn['connect_time'],
                                'end': now,
                                'sent': conn.get('bytes_sent', 0),
                                'received': conn.get('bytes_received', 0),
                                'duration': self._calculate_duration(conn['connect_time'], now)
                            }
                            self.stats_data['bandwidth'][client_name]['sessions'].append(session_data)
                        break
        
        self._save_stats()
    
    def _calculate_duration(self, start_time: str, end_time: str) -> int:
        """Calculate duration in seconds between two ISO timestamps"""
        try:
            start = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            end = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            return int((end - start).total_seconds())
        except Exception:
            return 0
    
    def update_concurrent_connections(self, current_count: int):
        """Update maximum concurrent connections if needed"""
        with self._stats_lock:
            if current_count > self.stats_data['summary']['max_concurrent_connections']:
                self.stats_data['summary']['max_concurrent_connections'] = current_count
        
        self._save_stats()
    
    def get_client_stats(self, client_name: str) -> Dict[str, Any]:
        """Get statistics for a specific client"""
        with self._stats_lock:
            connections = self.stats_data['connections'].get(client_name, [])
            bandwidth = self.stats_data['bandwidth'].get(client_name, {
                'total_sent': 0,
                'total_received': 0,
                'sessions': []
            })
            
            # Calculate additional metrics
            total_sessions = len(connections)
            active_sessions = len([c for c in connections if 'disconnect_time' not in c])
            
            # Calculate average session duration
            completed_sessions = [c for c in connections if 'disconnect_time' in c]
            avg_duration = 0
            if completed_sessions:
                total_duration = sum(
                    self._calculate_duration(c['connect_time'], c['disconnect_time'])
                    for c in completed_sessions
                )
                avg_duration = total_duration / len(completed_sessions)
            
            return {
                'client_name': client_name,
                'total_sessions': total_sessions,
                'active_sessions': active_sessions,
                'total_bandwidth_sent': bandwidth['total_sent'],
                'total_bandwidth_received': bandwidth['total_received'],
                'average_session_duration': int(avg_duration),
                'recent_connections': connections[-10:],  # Last 10 connections
                'bandwidth_history': bandwidth['sessions'][-20:]  # Last 20 sessions
            }
    
    def get_server_stats(self) -> Dict[str, Any]:
        """Get overall server statistics"""
        with self._stats_lock:
            now = datetime.now()
            last_7_days = now - timedelta(days=7)
            last_24_hours = now - timedelta(hours=24)
            
            # Count recent connections
            connections_7d = 0
            connections_24h = 0
            unique_clients_7d = set()
            unique_clients_24h = set()
            
            total_bandwidth_sent = 0
            total_bandwidth_received = 0
            
            for client_name, connections in self.stats_data['connections'].items():
                for conn in connections:
                    connect_time = datetime.fromisoformat(conn['connect_time'].replace('Z', '+00:00'))
                    
                    if connect_time >= last_7_days:
                        connections_7d += 1
                        unique_clients_7d.add(client_name)
                        
                    if connect_time >= last_24_hours:
                        connections_24h += 1
                        unique_clients_24h.add(client_name)
                    
                    total_bandwidth_sent += conn.get('bytes_sent', 0)
                    total_bandwidth_received += conn.get('bytes_received', 0)
            
            # Current active connections
            active_connections = 0
            for connections in self.stats_data['connections'].values():
                active_connections += len([c for c in connections if 'disconnect_time' not in c])
            
            return {
                'summary': self.stats_data['summary'],
                'active_connections': active_connections,
                'connections_last_7_days': connections_7d,
                'connections_last_24_hours': connections_24h,
                'unique_clients_last_7_days': len(unique_clients_7d),
                'unique_clients_last_24_hours': len(unique_clients_24h),
                'total_bandwidth_sent': total_bandwidth_sent,
                'total_bandwidth_received': total_bandwidth_received,
                'retention_days': self.retention_days,
                'last_updated': datetime.now().isoformat()
            }
    
    def get_bandwidth_history(self, client_name: Optional[str] = None, days: int = 7) -> List[Dict[str, Any]]:
        """Get bandwidth history for a client or all clients"""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        with self._stats_lock:
            if client_name:
                # Get history for specific client
                if client_name not in self.stats_data['bandwidth']:
                    return []
                
                sessions = self.stats_data['bandwidth'][client_name]['sessions']
                return [
                    session for session in sessions
                    if datetime.fromisoformat(session['start'].replace('Z', '+00:00')) >= cutoff_date
                ]
            else:
                # Get history for all clients
                all_sessions = []
                for client, bandwidth_data in self.stats_data['bandwidth'].items():
                    for session in bandwidth_data['sessions']:
                        if datetime.fromisoformat(session['start'].replace('Z', '+00:00')) >= cutoff_date:
                            session_copy = session.copy()
                            session_copy['client'] = client
                            all_sessions.append(session_copy)
                
                # Sort by start time
                all_sessions.sort(key=lambda x: x['start'], reverse=True)
                return all_sessions
    
    def export_stats(self) -> Dict[str, Any]:
        """Export all statistics data"""
        with self._stats_lock:
            return {
                'exported_at': datetime.now().isoformat(),
                'retention_days': self.retention_days,
                'data': self.stats_data.copy()
            }
    
    def import_stats(self, data: Dict[str, Any]):
        """Import statistics data"""
        try:
            with self._stats_lock:
                if 'data' in data:
                    self.stats_data = data['data']
                    self._save_stats()
                    logger.info("Statistics data imported successfully")
                else:
                    raise ValueError("Invalid import data format")
        except Exception as e:
            logger.error(f"Error importing statistics: {e}")
            raise


# Singleton instance
_stats_manager = None

def get_stats_manager(stats_file: str = '/var/lib/easyvpn/stats.json', retention_days: int = 7) -> StatsManager:
    """Get the global stats manager instance"""
    global _stats_manager
    if _stats_manager is None:
        _stats_manager = StatsManager(stats_file, retention_days)
    return _stats_manager 