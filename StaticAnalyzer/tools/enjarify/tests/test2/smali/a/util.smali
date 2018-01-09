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
.class public Lutil;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static print(Ljava/lang/String;)V
    .locals 1
    const-string v0, "minimalFOO"
    invoke-static {v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    return-void
.end method

.method public static print(I)V
    .locals 1

    invoke-static {p0}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;
    move-result-object v0

    invoke-static {v0}, Lutil;->print(Ljava/lang/String;)V
    return-void
.end method

.method public static print(F)V
    .locals 1

    invoke-static {p0}, Ljava/lang/Float;->toHexString(F)Ljava/lang/String;
    move-result-object v0

    invoke-static {v0}, Lutil;->print(Ljava/lang/String;)V
    return-void
.end method

.method public static print(J)V
    .locals 1

    invoke-static {p0, p1}, Ljava/lang/Long;->toHexString(J)Ljava/lang/String;
    move-result-object v0

    invoke-static {v0}, Lutil;->print(Ljava/lang/String;)V
    return-void
.end method

.method public static print(D)V
    .locals 1

    invoke-static {p0, p1}, Ljava/lang/Double;->toHexString(D)Ljava/lang/String;
    move-result-object v0

    invoke-static {v0}, Lutil;->print(Ljava/lang/String;)V
    return-void
.end method

.method public static print(Ljava/lang/Object;)V
    .locals 13

    instance-of v0, p0, [I
    if-eqz v0, :else1
    invoke-static {p0}, Ljava/util/Arrays;->toString([I)Ljava/lang/String;
    move-result-object v0
    goto :end

:else1
    # invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;
    move-result-object v0

:end
    invoke-static {v0}, Lutil;->print(Ljava/lang/String;)V
    return-void
.end method