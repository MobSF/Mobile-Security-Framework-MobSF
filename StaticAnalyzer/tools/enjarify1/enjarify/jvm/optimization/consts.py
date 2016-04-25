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

import collections

from .. import scalartypes as scalars
from .. import ir

def allocateRequiredConstants(pool, long_irs):
    # see comments in writebytecode.finishCodeAttrs
    # We allocate the constants pretty much greedily. This is far from optimal,
    # but it shouldn't be a big deal since this code is almost never required
    # in the first place. In fact, there are no known real world classes that
    # even come close to exhausting the constant pool.

    # print('{} methods potentially too long'.format(len(long_irs)))
    # print(sorted([_ir.upper_bound for _ir in long_irs], reverse=True))
    # for _ir in long_irs:
    #     print(_ir.method.id.triple(), _ir.upper_bound)

    narrow_pairs = collections.Counter()
    wide_pairs = collections.Counter()
    alt_lens = {}
    for _ir in long_irs:
        for ins in _ir.flat_instructions:
            if isinstance(ins, ir.PrimConstant):
                key = ins.cpool_key()
                alt_lens[key] = len(ins.bytecode)
                if scalars.iswide(ins.st):
                    if len(ins.bytecode) > 3:
                        wide_pairs[key] += 1
                else:
                    if len(ins.bytecode) > 2:
                        narrow_pairs[key] += 1

    # see if already in the constant pool
    for x in pool.vals:
        del narrow_pairs[x]
        del wide_pairs[x]

    # if we have enough space for all required constants, preferentially allocate
    # most commonly used constants to first 255 slots
    if pool.space() >= len(narrow_pairs) + 2*len(wide_pairs) and pool.lowspace() > 0:
        # We can't use Counter.most_common here because it is nondeterminstic in
        # the case of ties.
        most_common = sorted(narrow_pairs, key=lambda p:(-narrow_pairs[p], p))
        for key in most_common[:pool.lowspace()]:
            pool.insertDirectly(key, True)
            del narrow_pairs[key]

    scores = {}
    for p, count in narrow_pairs.items():
        scores[p] = (alt_lens[p] - 3) * count
    for p, count in wide_pairs.items():
        scores[p] = (alt_lens[p] - 3) * count

    # sort by score
    narrowq = sorted(narrow_pairs, key=lambda p:(scores[p], p))
    wideq = sorted(wide_pairs, key=lambda p:(scores[p], p))
    while pool.space() >= 1 and (narrowq or wideq):
        if not narrowq and pool.space() < 2:
            break

        wscore = sum(scores[p] for p in wideq[-1:])
        nscore = sum(scores[p] for p in narrowq[-2:])
        if pool.space() >= 2 and wscore > nscore and wscore > 0:
            pool.insertDirectly(wideq.pop(), False)
        elif nscore > 0:
            pool.insertDirectly(narrowq.pop(), True)
        else:
            break
