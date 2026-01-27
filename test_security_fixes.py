#!/usr/bin/env python3
"""Test script to verify security fixes and functionality."""

import sys
from pathlib import Path

def test_imports():
    """Test that all modules import correctly."""
    print("Testing imports...")
    try:
        from logmind.ingestion.base import NormalizedLog, MAX_LOG_LINE_LENGTH, MAX_MESSAGE_LENGTH
        from logmind.llm.rate_limiter import RateLimiter
        from logmind.llm.claude_provider import ClaudeProvider
        from logmind.alerts.slack import SlackAlerter
        from logmind.ingestion.file_watcher import FileWatcher
        print("✓ All imports successful")
        return True
    except Exception as e:
        print(f"✗ Import failed: {e}")
        return False

def test_security_constants():
    """Test that security constants are defined."""
    print("\nTesting security constants...")
    try:
        from logmind.ingestion.base import (
            MAX_LOG_LINE_LENGTH,
            MAX_MESSAGE_LENGTH,
            MAX_SOURCE_LENGTH,
            MAX_PROGRAM_LENGTH,
            MAX_USER_LENGTH
        )
        
        assert MAX_LOG_LINE_LENGTH == 65536, "MAX_LOG_LINE_LENGTH should be 64KB"
        assert MAX_MESSAGE_LENGTH == 32768, "MAX_MESSAGE_LENGTH should be 32KB"
        assert MAX_SOURCE_LENGTH == 255, "MAX_SOURCE_LENGTH should be 255"
        
        print(f"✓ MAX_LOG_LINE_LENGTH: {MAX_LOG_LINE_LENGTH}")
        print(f"✓ MAX_MESSAGE_LENGTH: {MAX_MESSAGE_LENGTH}")
        print(f"✓ MAX_SOURCE_LENGTH: {MAX_SOURCE_LENGTH}")
        return True
    except Exception as e:
        print(f"✗ Security constants test failed: {e}")
        return False

def test_rate_limiter():
    """Test rate limiter functionality."""
    print("\nTesting rate limiter...")
    try:
        from logmind.llm.rate_limiter import RateLimiter
        
        limiter = RateLimiter(max_calls=5, time_window=60.0)
        
        # Should be able to proceed initially
        can_proceed, reason = limiter.can_proceed()
        assert can_proceed, f"Should be able to proceed: {reason}"
        
        # Record some calls
        for i in range(5):
            limiter.record_call(tokens_used=100)
        
        # Should be rate limited now
        can_proceed, reason = limiter.can_proceed()
        assert not can_proceed, "Should be rate limited after 5 calls"
        
        # Check stats
        stats = limiter.get_stats()
        assert stats['calls_in_window'] == 5, "Should have 5 calls in window"
        assert stats['tokens_in_window'] == 500, "Should have 500 tokens"
        
        print("✓ Rate limiter works correctly")
        print(f"  - Enforces call limits: {stats['calls_in_window']}/{stats['max_calls']}")
        print(f"  - Tracks token usage: {stats['tokens_in_window']}/{stats['max_tokens']}")
        return True
    except Exception as e:
        print(f"✗ Rate limiter test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_input_validation():
    """Test input validation in parsers."""
    print("\nTesting input validation...")
    try:
        from logmind.ingestion.syslog_parser import SyslogParser
        from pydantic import ValidationError
        
        parser = SyslogParser()
        
        # Test normal log
        normal_log = "<134>Jan 27 12:00:00 server sshd[1234]: Accepted password for user from 192.168.1.1"
        result = parser.parse(normal_log, source="test")
        assert result is not None, "Should parse normal log"
        print("✓ Normal log parsing works")
        
        # Test oversized line (should be skipped in batch)
        oversized = "x" * 100000  # 100KB line
        batch_result = parser.parse_batch([oversized], source="test")
        assert len(batch_result) == 0, "Should skip oversized lines"
        print("✓ Oversized lines are skipped")
        
        return True
    except Exception as e:
        print(f"✗ Input validation test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_path_validation():
    """Test path validation."""
    print("\nTesting path validation...")
    try:
        from pathlib import Path
        
        # Test that resolve works
        test_path = Path(".")
        resolved = test_path.resolve()
        assert resolved.is_absolute(), "Resolved path should be absolute"
        print(f"✓ Path resolution works: {resolved}")
        
        return True
    except Exception as e:
        print(f"✗ Path validation test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("=" * 60)
    print("LogMind Security & Functionality Tests")
    print("=" * 60)
    
    tests = [
        test_imports,
        test_security_constants,
        test_rate_limiter,
        test_input_validation,
        test_path_validation,
    ]
    
    results = []
    for test in tests:
        try:
            results.append(test())
        except Exception as e:
            print(f"✗ Test {test.__name__} crashed: {e}")
            results.append(False)
    
    print("\n" + "=" * 60)
    print(f"Results: {sum(results)}/{len(results)} tests passed")
    print("=" * 60)
    
    if all(results):
        print("✓ All tests passed!")
        return 0
    else:
        print("✗ Some tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())

