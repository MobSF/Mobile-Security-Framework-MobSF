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

class Options:
    def __init__(self, inline_consts=False, prune_store_loads=False,
        copy_propagation=False, remove_unused_regs=False, dup2ize=False,
        sort_registers=False, split_pool=False, delay_consts=False):
        self.inline_consts = inline_consts
        self.prune_store_loads = prune_store_loads
        self.copy_propagation = copy_propagation
        self.remove_unused_regs = remove_unused_regs
        self.dup2ize = dup2ize
        self.sort_registers = sort_registers
        self.split_pool = split_pool
        self.delay_consts = delay_consts

NONE = Options()
# Options which make the generated code more readable for humans
PRETTY = Options(inline_consts=True, prune_store_loads=True, copy_propagation=True, remove_unused_regs=True)
ALL = Options(inline_consts=True, prune_store_loads=True, copy_propagation=True, remove_unused_regs=True, dup2ize=True,
        sort_registers=True, split_pool=True, delay_consts=True)
