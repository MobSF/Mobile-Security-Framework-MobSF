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
.class public LL/util;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static trim(Ljava/lang/String;I)Ljava/lang/String;
    .locals 2
    invoke-virtual {p0}, Ljava/lang/String;->length()I
    move-result v1

    if-ge p1, v1, :endif
    move v1, p1
:endif

    const v0, 0
    invoke-virtual {p0, v0, v1}, Ljava/lang/String;->substring(II)Ljava/lang/String;
    move-result-object v1
    return-object v1
.end method

.method public static print(Ljava/lang/String;)V
    .locals 1
    const/16 v0, 4000
    invoke-static {p0, v0}, LL/util;->trim(Ljava/lang/String;I)Ljava/lang/String;
    move-result-object p0

    const-string v0, "minimalFOO"
    invoke-static {v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    return-void
.end method

.method public static print(I)V
    .locals 1

    invoke-static {p0}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;
    move-result-object v0

    invoke-static {v0}, LL/util;->print(Ljava/lang/String;)V
    return-void
.end method

.method public static print(F)V
    .locals 1

    invoke-static {p0}, Ljava/lang/Float;->toHexString(F)Ljava/lang/String;
    move-result-object v0

    invoke-static {v0}, LL/util;->print(Ljava/lang/String;)V
    return-void
.end method

.method public static print(J)V
    .locals 1

    invoke-static {p0, p1}, Ljava/lang/Long;->toHexString(J)Ljava/lang/String;
    move-result-object v0

    invoke-static {v0}, LL/util;->print(Ljava/lang/String;)V
    return-void
.end method

.method public static print(D)V
    .locals 1

    invoke-static {p0, p1}, Ljava/lang/Double;->toHexString(D)Ljava/lang/String;
    move-result-object v0

    invoke-static {v0}, LL/util;->print(Ljava/lang/String;)V
    return-void
.end method

.method public static toString([C)Ljava/lang/String;
    .locals 3
    const-string v0, "["
    const v1, 0

:loopstart

    if-eqz v1, :skipspace
    const-string v2, " "
    invoke-virtual {v0, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
:skipspace

    :try_start
    aget-char v2, p0, v1
    :try_end
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start .. :try_end} :loopend


    invoke-static {v2}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;
    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0

    add-int/lit8 v1, v1, 1
    goto :loopstart
:loopend
    const-string v2, "]"
    invoke-virtual {v0, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0

    return-object v0
.end method

.method public static toString([F)Ljava/lang/String;
    .locals 4
    const-string v0, "["
    const v1, 0

:loopstart

    if-eqz v1, :skipspace
    const-string v2, " "
    invoke-virtual {v0, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
:skipspace

    const v3, 300
    if-ge v1, v3, :loopend

    :try_start
    aget v2, p0, v1
    :try_end
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start .. :try_end} :loopend


    invoke-static {v2}, Ljava/lang/Float;->toHexString(F)Ljava/lang/String;
    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0

    add-int/lit8 v1, v1, 1
    goto :loopstart

:loopend
    const-string v2, "]"
    invoke-virtual {v0, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0

    return-object v0
.end method

.method public static toString([D)Ljava/lang/String;
    .locals 4
    const-string v0, "["
    const v1, 0

:loopstart

    if-eqz v1, :skipspace
    const-string v2, " "
    invoke-virtual {v0, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
:skipspace

    const v3, 300
    if-ge v1, v3, :loopend

    :try_start
    aget-wide v2, p0, v1
    :try_end
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start .. :try_end} :loopend


    invoke-static {v2, v3}, Ljava/lang/Double;->toHexString(D)Ljava/lang/String;
    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0

    add-int/lit8 v1, v1, 1
    goto :loopstart
:loopend
    const-string v2, "]"
    invoke-virtual {v0, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0

    return-object v0
.end method

.method public static toString([Ljava/lang/Object;)Ljava/lang/String;
    .locals 4
    const-string v0, "["
    const v1, 0

:loopstart

    if-eqz v1, :skipspace
    const-string v2, " "
    invoke-virtual {v0, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
:skipspace

    const v3, 300
    if-ge v1, v3, :loopend

    :try_start
    aget-object v2, p0, v1
    :try_end
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start .. :try_end} :loopend


    invoke-static {v2}, LL/util;->toString(Ljava/lang/Object;)Ljava/lang/String;
    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0

    add-int/lit16 v1, v1, 1
    goto :loopstart

:loopend
    const-string v2, "]"
    invoke-virtual {v0, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0

    return-object v0
.end method









.method public static toString(Ljava/lang/Object;)Ljava/lang/String;
    .locals 13

    instance-of v0, p0, Ljava/lang/Throwable;
    if-eqz v0, :end0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    move-result-object p0
:end0


    instance-of v0, p0, [I
    if-eqz v0, :else1
    invoke-static {p0}, Ljava/util/Arrays;->toString([I)Ljava/lang/String;
    move-result-object v0
    goto :end
:else1

    move-object v1, p0
    instance-of v0, v1, [B
    if-eqz v0, :else2
    invoke-static {p0}, Ljava/util/Arrays;->toString([B)Ljava/lang/String;
    move-result-object v0
    goto :end
:else2

# bad
    instance-of v0, p0, [Z
    if-eqz v0, :else3
    invoke-static {p0}, Ljava/util/Arrays;->toString([Z)Ljava/lang/String;
    move-result-object v0
    goto :end
:else3

    move-object v1, p0
    instance-of v0, v1, [C
    if-nez v0, :then4
:else4

    instance-of v0, p0, [S
    if-nez v0, :then5
:else5

    nop
    nop
    nop

    instance-of v0, p0, [J
    if-eqz v0, :else6
    invoke-static {p0}, Ljava/util/Arrays;->toString([J)Ljava/lang/String;
    move-result-object v0
    goto :end
:else6

    instance-of v0, p0, [D
    if-eqz v0, :else7
    invoke-static {p0}, LL/util;->toString([D)Ljava/lang/String;
    move-result-object v0
    goto :end
:else7

    instance-of v0, p0, [F
    if-eqz v0, :else8
    invoke-static {p0}, LL/util;->toString([F)Ljava/lang/String;
    move-result-object v0
    goto :end
:else8

    instance-of v0, p0, [Ljava/lang/Object;
    if-eqz v0, :else9
    invoke-static {p0}, LL/util;->toString([Ljava/lang/Object;)Ljava/lang/String;
    move-result-object v0
    goto :end
:else9



    # invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;
    move-result-object v0
    goto :end

:then4
    invoke-static {p0}, LL/util;->toString([C)Ljava/lang/String;
    move-result-object v0
    goto :end

:then5
    invoke-static {p0}, Ljava/util/Arrays;->toString([S)Ljava/lang/String;
    move-result-object v0
    # goto :end

:end
    return-object v0
.end method

.method public static print(Ljava/lang/Object;)V
    .locals 0
    invoke-static {p0}, LL/util;->toString(Ljava/lang/Object;)Ljava/lang/String;
    move-result-object p0
    invoke-static {p0}, LL/util;->print(Ljava/lang/String;)V
    return-void
.end method