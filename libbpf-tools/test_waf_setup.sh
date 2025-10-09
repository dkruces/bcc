#!/usr/bin/env bash
# WAF Testing Setup Script
# Run this on the VM to test the new WAF feature

set -euo pipefail

echo "=== WAF Feature Test Setup ==="
echo ""

# Check if blkalgn exists
if [ ! -f "./blkalgn" ]; then
    echo "ERROR: blkalgn binary not found in current directory"
    echo "Please copy blkalgn to this directory first"
    exit 1
fi

# Check for required tools
echo "Checking for required tools..."
if ! command -v fio &> /dev/null; then
    echo "ERROR: fio not found. Please install: sudo apt-get install fio"
    exit 1
fi

if ! command -v sudo &> /dev/null; then
    echo "ERROR: sudo not found"
    exit 1
fi

# Check for nvme device
if [ ! -b /dev/nvme0n1 ]; then
    echo "ERROR: /dev/nvme0n1 not found"
    echo "Available block devices:"
    ls -l /dev/nvme* /dev/sd* 2>/dev/null || echo "No devices found"
    exit 1
fi

echo "✓ All prerequisites met"
echo ""

# Create test script
cat > test_waf_workload.sh << 'TESTSCRIPT'
#!/usr/bin/env bash
set -euxo pipefail

echo "=== Running WAF Test Workload ==="

# Run blkalgn in background
sudo /tmp/blkalgn --disk=nvme0n1 --json=/tmp/blkalgn_waf_test.json &
BLKALGN_PID=$!

# Give it time to attach
sleep 2

# Generate test workload with known alignment patterns
# 3x 64KB at perfect alignment (64K)
sudo fio -bs=64k -iodepth=1 -rw=write -ioengine=sync -size=64k \
    -name=test -direct=1 -filename=/dev/nvme0n1 -loops=3 -offset=0

# 3x 64KB at 4K alignment (poor)
sudo fio -bs=64k -iodepth=1 -rw=write -ioengine=sync -size=64k \
    -name=test -direct=1 -filename=/dev/nvme0n1 -loops=3 -offset=4096

# 3x 64KB at 16K alignment (moderate)
sudo fio -bs=64k -iodepth=1 -rw=write -ioengine=sync -size=64k \
    -name=test -direct=1 -filename=/dev/nvme0n1 -loops=3 -offset=16384

# 3x 128KB at perfect alignment
sudo fio -bs=128k -iodepth=1 -rw=write -ioengine=sync -size=128k \
    -name=test -direct=1 -filename=/dev/nvme0n1 -loops=3 -offset=0

# 3x 128KB at 4K alignment (poor)
sudo fio -bs=128k -iodepth=1 -rw=write -ioengine=sync -size=128k \
    -name=test -direct=1 -filename=/dev/nvme0n1 -loops=3 -offset=4096

# 3x 512KB at perfect alignment
sudo fio -bs=512k -iodepth=1 -rw=write -ioengine=sync -size=512k \
    -name=test -direct=1 -filename=/dev/nvme0n1 -loops=3 -offset=0

# 3x 512KB at 4K alignment (poor)
sudo fio -bs=512k -iodepth=1 -rw=write -ioengine=sync -size=512k \
    -name=test -direct=1 -filename=/dev/nvme0n1 -loops=3 -offset=4096

# Wait a bit for blkalgn to process
sleep 2

# Stop blkalgn
echo ""
echo "=== Stopping blkalgn ==="
sudo kill -INT $BLKALGN_PID
wait $BLKALGN_PID 2>/dev/null || true

echo ""
echo "=== Test Complete ==="
echo "Check output above for WAF table"
echo "JSON output saved to: /tmp/blkalgn_waf_test.json"

TESTSCRIPT

chmod +x test_waf_workload.sh

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To run the test:"
echo "  ./test_waf_workload.sh"
echo ""
echo "Expected results:"
echo "  - You should see WAF table with IU sizes from 4KB to 8MB"
echo "  - For IU=16KB, expect WWAF around 1.08-1.10"
echo "  - Larger IUs will show higher amplification"
echo "  - JSON file will contain 'waf' section with detailed stats"
echo ""
echo "To view JSON output:"
echo "  cat /tmp/blkalgn_waf_test.json | jq '.disks.nvme0n1.waf'"
echo ""
