#!/usr/bin/env bash

# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# Try to find a valid python3 command, preferring pypy if available
function guess {
	if [ -z "$PYTHON" ]; then
		result=$($1 -c "print(range)" 2>/dev/null)
		if [ "$result" = "<class 'range'>" ]; then
			PYTHON=$1
		fi
	fi
}

guess "pypy3"
guess "python3"
guess "pypy"
guess "python"

if [ -z "$PYTHON" ]; then
	echo "Unable to find python3 on path"
else
	echo "Using $PYTHON as Python interpreter"

	# Find location of this bash script, and set its directory as the PYTHONPATH
	export PYTHONPATH=$(dirname "$(readlink "${BASH_SOURCE[0]}")")

	# Now execute the actual program
	exec $PYTHON -O -m enjarify.main "$@"
fi
