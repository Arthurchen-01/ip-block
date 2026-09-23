"""启动仪表盘的入口。桌面快捷方式用这个。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from eg.dashboard import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
