// Copyright 2015 Google Inc. All Rights Reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

public class Main {
	private android.util.Log a;
	private android.os.Bundle b;
	private android.app.Activity c;

	public static void main(String[] args) {
		try{
			Class<?> c = Class.forName(args[0]);
			java.lang.reflect.Constructor ctr = c.getDeclaredConstructor();
			Object o = ctr.newInstance();

			java.lang.reflect.Method m = c.getDeclaredMethod("onCreate", android.os.Bundle.class);
			m.invoke(o, (Object)null);
		} catch (Throwable t) {
			t.printStackTrace();
		}
	}
}