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
.class abstract public LFinal;
.super L-2;

.field public x:I

.method public constructor <init>()V
    .locals 1
    const-string v0, "Final <init>()V"
    invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V


    #iget v0, p0, LFinal;->x:I
    #invoke-static {v0}, LL/util;->print(I)V


    invoke-direct {p0}, L-2;-><init>()V
    const v0, -1
    invoke-virtual {p0, v0}, LFinal;->init-cb(I)I
    return-void
.end method

.method public constructor <init>(I)V
    .locals 1
    const-string v0, "Final <init>(I)V"
    invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V

    #iget v0, p0, LFinal;->x:I
    #invoke-static {v0}, LL/util;->print(I)V



    invoke-direct {p0}, L-2;-><init>()V
    invoke-virtual {p0, p1}, LFinal;->init-cb(I)I
    return-void
.end method

.method abstract public init-cb(I)I
.end method
