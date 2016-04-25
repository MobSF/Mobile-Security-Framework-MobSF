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
.class public final Lfinal;
.super LFinal;

.field public x:I
#.field private x:I

.method public constructor <init>()V
    .locals 1
    const-string v0, "final <init>()V"
    invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V



    invoke-direct {p0}, LFinal;-><init>()V

    const v0, 10
    iput v0, p0, Lfinal;->x:I

    const v0, 0
    invoke-virtual {p0, v0}, LFinal;->init-cb(I)I
    return-void
.end method

.method public constructor <init>(I)V
    .locals 1
    const-string v0, "final <init>(I)V"
    invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V

    const v0, 170
    iput v0, p0, Lfinal;->x:I
    #iget v0, p0, Lfinal;->x:I

    invoke-direct {p0, p1}, LFinal;-><init>(I)V

    iget v0, p0, LFinal;->x:I

    const v0, 210
    iput v0, p0, Lfinal;->x:I

    const v0, 0
    invoke-virtual {p0, v0}, LFinal;->init-cb(I)I
    return-void
.end method

.method public init-cb(I)I
    .locals 1
    iget v0, p0, Lfinal;->x:I
    xor-int/2addr v0, p1
    invoke-static {v0}, LL/util;->print(I)V

    return p1
.end method