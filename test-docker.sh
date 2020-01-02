#!/bin/bash -e

VERSION=$(mvn -q \
    -Dexec.executable="echo" \
    -Dexec.args='${project.version}' \
    --non-recursive \
    org.codehaus.mojo:exec-maven-plugin:1.3.1:exec)

SCAN_TARGET="./cli/target/release/lib"

if [ ! -d "$SCAN_TARGET" ]; then 
  echo "Scan target does not exist: $SCAN_TARGET"
  exit 1
fi

cd $SCAN_TARGET
OWASPDC_DIRECTORY=$HOME/OWASP-Dependency-Check
DATA_DIRECTORY="$OWASPDC_DIRECTORY/data"
REPORT_DIRECTORY="$OWASPDC_DIRECTORY/reports"
CACHE_DIRECTORY="$OWASPDC_DIRECTORY/data/cache"

if [ ! -d "$DATA_DIRECTORY" ]; then
    echo "Initially creating persistent directory: $DATA_DIRECTORY"
    mkdir -p "$DATA_DIRECTORY"
fi

if [ ! -d "$REPORT_DIRECTORY" ]; then
    echo "Initially creating persistent directory: $REPORT_DIRECTORY"
    mkdir -p "$REPORT_DIRECTORY"
fi

if [ ! -d "$CACHE_DIRECTORY" ]; then
    echo "Initially creating persistent directory: $CACHE_DIRECTORY"
    mkdir -p "$CACHE_DIRECTORY"
fi

if [ -f "$HOME/OWASP-Dependency-Check/reports/dependency-check-report.json" ]; then
    rm "$HOME/OWASP-Dependency-Check/reports/dependency-check-report.json"
fi

# Make sure we are using the latest version
# docker pull owasp/dependency-check

docker run --rm \
    --volume $(pwd):/src \
    --volume "$DATA_DIRECTORY":/usr/share/dependency-check/data \
    --volume "$REPORT_DIRECTORY":/report \
    owasp/dependency-check:$VERSION  \
    --scan /src \
    --format "ALL" \
    --log /report/odc.log \
    --out /report
    # Use suppression like this: (/src == $pwd)
    # --suppression "/src/security/dependency-check-suppression.xml"

# return to original working directory
cd -

echo ""
grep -oF "dependency-check-core-$VERSION.jar" $HOME/OWASP-Dependency-Check/reports/dependency-check-report.json  > /dev/null 2>&1
if [[ "$?" -eq 0 ]] ; then
  echo "SUCCESS - dependency-check docker test passed"
else
  echo "FAILED - dependency-check docker test failed"
  exit 1
fi
