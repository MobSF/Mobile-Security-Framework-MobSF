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
.class public La/a;
.super Landroid/app/Activity;

.field public static f:Ljava/lang/String;="Hello, World!"
.field public static F:Ljava/lang/String;
.field public static f:I=555
.field public static f:Z=true
.field public static f:F=NANf


.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroid/app/Activity;-><init>()V

    return-void
.end method

.method public static print(Ljava/lang/String;)V
    .locals 1
    const-string v0, "minimalFOO"
    invoke-static {v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    return-void
.end method

.method public static print(Ljava/lang/Object;)V
    .locals 1
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;
    move-result-object v0

    invoke-static {v0}, La/a;->print(Ljava/lang/String;)V
    return-void
.end method

.method public static print(I)V
    .locals 1

    invoke-static {p0}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;
    move-result-object v0

    invoke-static {v0}, La/a;->print(Ljava/lang/String;)V
    return-void
.end method

.method public static print(F)V
    .locals 1

    invoke-static {p0}, Ljava/lang/Float;->toHexString(F)Ljava/lang/String;
    move-result-object v0

    invoke-static {v0}, La/a;->print(Ljava/lang/String;)V
    return-void
.end method

.method public static print(J)V
    .locals 1

    invoke-static {p0, p1}, Ljava/lang/Long;->toHexString(J)Ljava/lang/String;
    move-result-object v0

    invoke-static {v0}, La/a;->print(Ljava/lang/String;)V
    return-void
.end method

.method public static print(D)V
    .locals 1

    invoke-static {p0, p1}, Ljava/lang/Double;->toHexString(D)Ljava/lang/String;
    move-result-object v0

    invoke-static {v0}, La/a;->print(Ljava/lang/String;)V
    return-void
.end method

.method public static testWideConstSub(II)V
    .locals 2

    if-nez p0, :else1
        const-wide v0, 0x0123456789ABCDEFl
        goto :end1
    :else1
        # const-wide v0, 0xfff1000000000000l
        const-wide/high16 v0, 0xfff1
    :end1

    if-nez p1, :else2
        invoke-static {v0, v1}, La/a;->print(J)V
        goto :end2
    :else2
        invoke-static {v0, v1}, La/a;->print(D)V
    :end2

    return-void
.end method

.method public static testWideConst()V
    .locals 2
    const/4 v0, 0
    const/4 v1, 0
    invoke-static {v0, v1}, La/a;->testWideConstSub(II)V
    const/4 v1, 1
    invoke-static {v0, v1}, La/a;->testWideConstSub(II)V
    const/4 v0, 1
    invoke-static {v0, v1}, La/a;->testWideConstSub(II)V
    const/4 v1, 0
    invoke-static {v0, v1}, La/a;->testWideConstSub(II)V
    return-void
.end method

.method public static testFillArray()V
    .locals 14

    const/16 v0, 37
    new-array v0, v0, [I
    fill-array-data v0, :ArrayData

    const/4 v1, 0
    :loopstart1
        :try_start1
        aget v2, v0, v1
        :try_end1

        invoke-static {v2}, La/a;->print(I)V
        add-int/lit16 v1, v1, 1
        goto :loopstart1

    .catchall {:try_start1 .. :try_end1} :loopend1
    :loopend1

    const/16 v0, 38
    new-array v0, v0, [F
    fill-array-data v0, :ArrayData

    const/4 v1, 0
    :loopstart2
        :try_start2
        aget v2, v0, v1
        :try_end2

        invoke-static {v2}, La/a;->print(F)V
        add-int/lit16 v1, v1, 1
        goto :loopstart2

    .catchall {:try_start2 .. :try_end2} :loopend2
    :loopend2
    return-void

:ArrayData
    .array-data 4
        1.0f 2.0f 3.0f 234.3f NaNf InfinityF -InfinityF 0.0 -0.0 0.5 17e17
        0 1 2 3 4 5 6 -1 -2 -3 0xFFFF 0xFFAA -0xFFFF 128 -128 0x7FFFFFFF
        0xDEADBEEF 42 1337
    .end array-data
.end method

.method public static _([B)[Z
    .locals 0
    const/4 p0, 0
    return-object p0
.end method

.method public static _(JLjava/lang/Long;[J)Ljava/lang/String;
    .locals 0
    const/4 p0, 0
    return-object p0
.end method



.method public onCreate(Landroid/os/Bundle;)V
    .locals 14
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    invoke-static {}, La/a;->testWideConst()V
    invoke-static {}, La/a;->testFillArray()V
    return-void
.end method
