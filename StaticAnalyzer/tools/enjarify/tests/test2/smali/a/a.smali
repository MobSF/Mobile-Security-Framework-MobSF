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

.field public static f:Ljava/lang/String;="Code"
.field public static F:Ljava/lang/String;
.field public static f:I=555
.field public static f:Z=true
.field public static F:Z=32
.field public static f:F=NANf
.field public static f:J=555.555
.field public static f:D
.field public i:F
.field public i:B

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method public static testConstsSub(III)F
    .locals 4
    const/high16 v3, 0
    move v0, v3
    move v2, v3
    move v3, p0

    if-nez p1, :elsePrim


    if-nez v3, :else1
        const-string/jumbo v2, "Hello, World!"
        goto/16 :end1
    :else1
        move/from16 v2, v2
    :end1
    invoke-static {v2}, Lutil;->print(Ljava/lang/Object;)V
    return v0


    :elsePrim
    const v1, 127

    if-eqz p0, :end0
        rsub-int/lit8 v1, v3, 2

        if-eqz v1, :else2
            const/16 v2, -32768
            goto/16 :end2
        :else2
            const v2, -32.768f
        :end2
    :end0

    move/16 v0, v2
    move v2, v0
    move v3, v1

    if-nez p2, :else3
        invoke-static {v0}, Lutil;->print(I)V
        invoke-static {v2}, Lutil;->print(F)V
        goto/32 :end3
    :else3
        invoke-static {v0}, Lutil;->print(F)V
        invoke-static {v2}, Lutil;->print(I)V
        int-to-float v2, v3
    :end3

    return v2
.end method

.method public static testConsts()V
    .locals 4
    const-string v0, "testConsts"
    invoke-static {v0}, Lutil;->print(Ljava/lang/String;)V

    const/4 v0, 0
    const v1, 0
    const v2, 0

    invoke-static {v0, v1, v2}, La/a;->testConstsSub(III)F
    move-result v3
    invoke-static {v3}, Lutil;->print(F)V
    const v0, 1
    invoke-static {v0, v1, v2}, La/a;->testConstsSub(III)F
    move-result v3
    invoke-static {v3}, Lutil;->print(F)V


    move/16 v2, v1
    move/16 v1, v0
    invoke-static {v0, v1, v2}, La/a;->testConstsSub(III)F
    move-result v3
    invoke-static {v3}, Lutil;->print(F)V
    const v0, 2
    invoke-static {v0, v1, v2}, La/a;->testConstsSub(III)F
    move-result v3
    invoke-static {v3}, Lutil;->print(F)V
    const v0, 0
    invoke-static {v0, v1, v2}, La/a;->testConstsSub(III)F
    move-result v3
    invoke-static {v3}, Lutil;->print(F)V

    const v0, 1
    const v2, 1
    invoke-static {v0, v1, v2}, La/a;->testConstsSub(III)F
    move-result v3
    invoke-static {v3}, Lutil;->print(F)V
    const v0, 2
    invoke-static {v0, v1, v2}, La/a;->testConstsSub(III)F
    move-result v3
    invoke-static {v3}, Lutil;->print(F)V
    const v0, 0
    invoke-static {v0, v1, v2}, La/a;->testConstsSub(III)F
    move-result v3
    invoke-static {v3}, Lutil;->print(F)V

    return-void
.end method

.method public testFields()V
    .locals 1
    const-string v0, "testFields"
    invoke-static {v0}, Lutil;->print(Ljava/lang/String;)V

    iget v0, p0, La/a;->i:F
    invoke-static {v0}, Lutil;->print(F)V
    iget-byte v0, p0, La/a;->i:B
    invoke-static {v0}, Lutil;->print(I)V

    sget-object v0, La/a;->f:Ljava/lang/String;
    invoke-static {v0}, Lutil;->print(Ljava/lang/Object;)V
    sget-object v0, La/a;->F:Ljava/lang/String;
    invoke-static {v0}, Lutil;->print(Ljava/lang/Object;)V
    sget v0, La/a;->f:I
    invoke-static {v0}, Lutil;->print(I)V
    sget-boolean v0, La/a;->f:Z
    invoke-static {v0}, Lutil;->print(I)V
    sget-boolean v0, La/a;->F:Z
    invoke-static {v0}, Lutil;->print(I)V
    sget v0, La/a;->f:F
    invoke-static {v0}, Lutil;->print(F)V
    sget-wide v0, La/a;->f:J
    invoke-static {v0, p0}, Lutil;->print(J)V
    sget-wide v0, La/a;->f:D
    invoke-static {v0, p0}, Lutil;->print(D)V

    return-void
.end method

.method public static testFillArraySub(II)[I
    .locals 1

    filled-new-array {p0, p1, p0, p1, p0}, [I
    move-result-object v0
    goto :rest

:ArrayData
    .array-data 4
    .end array-data
:ArrayData2
    .array-data 4
        100 101 102 103
    .end array-data

:else
    fill-array-data v0, :ArrayData
    return-object v0

:rest
    if-lt p0, p1, :else
    fill-array-data v0, :ArrayData2
    return-object v0
.end method

.method public static testFillArray()V
    .locals 3
    const-string v0, "testFillArray"
    invoke-static {v0}, Lutil;->print(Ljava/lang/String;)V

    const/16 v0, 32767
    const/16 v1, -32768

    invoke-static {v0, v1}, La/a;->testFillArraySub(II)[I
    move-result-object v2
    invoke-static {v2}, Lutil;->print(Ljava/lang/Object;)V

    mul-int/2addr v0, v1

    invoke-static {v0, v1}, La/a;->testFillArraySub(II)[I
    move-result-object v2
    invoke-static {v2}, Lutil;->print(Ljava/lang/Object;)V

    const v0, 0
    invoke-static {v0}, Lutil;->print(Ljava/lang/Object;)V
    return-void
.end method


.method public onCreate(Landroid/os/Bundle;)V
    .locals 14
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    invoke-static {}, La/a;->testConsts()V
    invoke-virtual {p0}, La/a;->testFields()V
    invoke-static {}, La/a;->testFillArray()V

    return-void
.end method
