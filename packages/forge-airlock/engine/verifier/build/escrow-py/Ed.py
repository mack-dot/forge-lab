import sys
from typing import Callable, Any, TypeVar, NamedTuple
from math import floor
from itertools import count

import module_ as module_
import _dafny as _dafny
import System_ as System_
import Sha as Sha

# Module: Ed

class default__:
    def  __init__(self):
        pass

    @staticmethod
    def Fp(a):
        return _dafny.euclidian_modulus(a, default__.P)

    @staticmethod
    def Mul(a, b):
        return _dafny.euclidian_modulus((a) * (b), default__.P)

    @staticmethod
    def Add(a, b):
        return _dafny.euclidian_modulus((a) + (b), default__.P)

    @staticmethod
    def Sub(a, b):
        return _dafny.euclidian_modulus((_dafny.euclidian_modulus((a) - (b), default__.P)) + (default__.P), default__.P)

    @staticmethod
    def ModPow(base, exp, m):
        r: int = int(0)
        r = _dafny.euclidian_modulus(1, m)
        d_0_b_: int
        d_0_b_ = _dafny.euclidian_modulus((_dafny.euclidian_modulus(base, m)) + (m), m)
        d_1_e_: int
        d_1_e_ = exp
        while (d_1_e_) > (0):
            if (_dafny.euclidian_modulus(d_1_e_, 2)) == (1):
                r = _dafny.euclidian_modulus((r) * (d_0_b_), m)
            d_0_b_ = _dafny.euclidian_modulus((d_0_b_) * (d_0_b_), m)
            d_1_e_ = _dafny.euclidian_division(d_1_e_, 2)
        return r

    @staticmethod
    def Inv(a):
        r: int = int(0)
        out0_: int
        out0_ = default__.ModPow(_dafny.euclidian_modulus((_dafny.euclidian_modulus(a, default__.P)) + (default__.P), default__.P), (default__.P) - (2), default__.P)
        r = out0_
        return r

    @staticmethod
    def PAdd(p1, p2):
        r: Point = Point.default()()
        d_0_x1_: int
        d_0_x1_ = _dafny.euclidian_modulus((_dafny.euclidian_modulus((p1).x, default__.P)) + (default__.P), default__.P)
        d_1_y1_: int
        d_1_y1_ = _dafny.euclidian_modulus((_dafny.euclidian_modulus((p1).y, default__.P)) + (default__.P), default__.P)
        d_2_x2_: int
        d_2_x2_ = _dafny.euclidian_modulus((_dafny.euclidian_modulus((p2).x, default__.P)) + (default__.P), default__.P)
        d_3_y2_: int
        d_3_y2_ = _dafny.euclidian_modulus((_dafny.euclidian_modulus((p2).y, default__.P)) + (default__.P), default__.P)
        d_4_x1y2_: int
        d_4_x1y2_ = default__.Mul(d_0_x1_, d_3_y2_)
        d_5_y1x2_: int
        d_5_y1x2_ = default__.Mul(d_1_y1_, d_2_x2_)
        d_6_y1y2_: int
        d_6_y1y2_ = default__.Mul(d_1_y1_, d_3_y2_)
        d_7_x1x2_: int
        d_7_x1x2_ = default__.Mul(d_0_x1_, d_2_x2_)
        d_8_dxy_: int
        d_8_dxy_ = default__.Mul(default__.Mul(default__.D, d_7_x1x2_), d_6_y1y2_)
        d_9_xnum_: int
        d_9_xnum_ = default__.Add(d_4_x1y2_, d_5_y1x2_)
        d_10_xden_: int
        d_10_xden_ = default__.Add(_dafny.euclidian_modulus(1, default__.P), d_8_dxy_)
        d_11_ynum_: int
        d_11_ynum_ = default__.Add(d_6_y1y2_, d_7_x1x2_)
        d_12_yden_: int
        d_12_yden_ = default__.Sub(_dafny.euclidian_modulus(1, default__.P), d_8_dxy_)
        d_13_xdi_: int
        out0_: int
        out0_ = default__.Inv(d_10_xden_)
        d_13_xdi_ = out0_
        d_14_ydi_: int
        out1_: int
        out1_ = default__.Inv(d_12_yden_)
        d_14_ydi_ = out1_
        r = Point_Pt(default__.Mul(d_9_xnum_, d_13_xdi_), default__.Mul(d_11_ynum_, d_14_ydi_))
        return r

    @staticmethod
    def PDouble(p1):
        r: Point = Point.default()()
        out0_: Point
        out0_ = default__.PAdd(p1, p1)
        r = out0_
        return r

    @staticmethod
    def PEq(a, b):
        return ((_dafny.euclidian_modulus((_dafny.euclidian_modulus((a).x, default__.P)) + (default__.P), default__.P)) == (_dafny.euclidian_modulus((_dafny.euclidian_modulus((b).x, default__.P)) + (default__.P), default__.P))) and ((_dafny.euclidian_modulus((_dafny.euclidian_modulus((a).y, default__.P)) + (default__.P), default__.P)) == (_dafny.euclidian_modulus((_dafny.euclidian_modulus((b).y, default__.P)) + (default__.P), default__.P)))

    @staticmethod
    def ScalarMul(k, p0):
        r: Point = Point.default()()
        r = default__.IDENT
        d_0_bits_: int
        d_0_bits_ = 0
        d_1_t_: int
        d_1_t_ = k
        while (d_1_t_) > (0):
            d_0_bits_ = (d_0_bits_) + (1)
            d_1_t_ = _dafny.euclidian_division(d_1_t_, 2)
        d_2_i_: int
        d_2_i_ = (d_0_bits_) - (1)
        while (d_2_i_) >= (0):
            out0_: Point
            out0_ = default__.PDouble(r)
            r = out0_
            d_3_bit_: int
            d_3_bit_ = _dafny.euclidian_modulus(_dafny.euclidian_division(k, default__.Pow2(d_2_i_)), 2)
            if (d_3_bit_) == (1):
                out1_: Point
                out1_ = default__.PAdd(r, p0)
                r = out1_
            d_2_i_ = (d_2_i_) - (1)
        return r

    @staticmethod
    def Pow2(n):
        d_0___accumulator_ = 1
        while True:
            with _dafny.label():
                if (n) == (0):
                    return (1) * (d_0___accumulator_)
                elif True:
                    d_0___accumulator_ = (d_0___accumulator_) * (2)
                    in0_ = (n) - (1)
                    n = in0_
                    raise _dafny.TailCall()
                break

    @staticmethod
    def LEInt(s, off, n):
        if (n) == (0):
            return 0
        elif True:
            return ((s)[off]) + ((256) * (default__.LEInt(s, (off) + (1), (n) - (1))))

    @staticmethod
    def DecodePoint(enc):
        ok: bool = False
        pt: Point = Point.default()()
        d_0_yfull_: int
        d_0_yfull_ = default__.LEInt(enc, 0, 32)
        d_1_sign_: int
        d_1_sign_ = _dafny.euclidian_modulus(_dafny.euclidian_division(d_0_yfull_, default__.Pow2(255)), 2)
        d_2_y_: int
        d_2_y_ = _dafny.euclidian_modulus(d_0_yfull_, default__.Pow2(255))
        if (d_2_y_) >= (default__.P):
            ok = False
            pt = default__.IDENT
            return ok, pt
        d_3_y2_: int
        d_3_y2_ = default__.Mul(d_2_y_, d_2_y_)
        d_4_u_: int
        d_4_u_ = default__.Sub(d_3_y2_, _dafny.euclidian_modulus(1, default__.P))
        d_5_v_: int
        d_5_v_ = default__.Add(default__.Mul(default__.D, d_3_y2_), _dafny.euclidian_modulus(1, default__.P))
        d_6_v2_: int
        d_6_v2_ = default__.Mul(d_5_v_, d_5_v_)
        d_7_v3_: int
        d_7_v3_ = default__.Mul(d_6_v2_, d_5_v_)
        d_8_v7_: int
        d_8_v7_ = default__.Mul(default__.Mul(d_7_v3_, d_7_v3_), d_5_v_)
        d_9_uv7_: int
        d_9_uv7_ = default__.Mul(d_4_u_, d_8_v7_)
        d_10_pm5d8_: int
        d_10_pm5d8_ = _dafny.euclidian_division((default__.P) - (5), 8)
        d_11_pw_: int
        out0_: int
        out0_ = default__.ModPow(d_9_uv7_, d_10_pm5d8_, default__.P)
        d_11_pw_ = out0_
        d_12_x_: int
        d_12_x_ = default__.Mul(default__.Mul(d_4_u_, d_7_v3_), d_11_pw_)
        d_13_vx2_: int
        d_13_vx2_ = default__.Mul(d_5_v_, default__.Mul(d_12_x_, d_12_x_))
        if (d_13_vx2_) != (_dafny.euclidian_modulus((_dafny.euclidian_modulus(d_4_u_, default__.P)) + (default__.P), default__.P)):
            d_14_x2_: int
            d_14_x2_ = default__.Mul(d_12_x_, default__.SQRTM1)
            d_15_vx2b_: int
            d_15_vx2b_ = default__.Mul(d_5_v_, default__.Mul(d_14_x2_, d_14_x2_))
            if (d_15_vx2b_) != (_dafny.euclidian_modulus((_dafny.euclidian_modulus(d_4_u_, default__.P)) + (default__.P), default__.P)):
                ok = False
                pt = default__.IDENT
                return ok, pt
            d_12_x_ = d_14_x2_
        if (d_12_x_) == (0):
            if (d_1_sign_) == (1):
                ok = False
                pt = default__.IDENT
                return ok, pt
        elif True:
            if (_dafny.euclidian_modulus(d_12_x_, 2)) != (d_1_sign_):
                d_12_x_ = _dafny.euclidian_modulus((_dafny.euclidian_modulus((default__.P) - (d_12_x_), default__.P)) + (default__.P), default__.P)
        ok = True
        pt = Point_Pt(d_12_x_, d_2_y_)
        return ok, pt

    @staticmethod
    def IsSmallOrder(p0):
        b: bool = False
        d_0_p1_: Point
        out0_: Point
        out0_ = default__.PDouble(p0)
        d_0_p1_ = out0_
        d_1_p2_: Point
        out1_: Point
        out1_ = default__.PDouble(d_0_p1_)
        d_1_p2_ = out1_
        d_2_p3_: Point
        out2_: Point
        out2_ = default__.PDouble(d_1_p2_)
        d_2_p3_ = out2_
        b = default__.PEq(d_2_p3_, default__.IDENT)
        return b

    @staticmethod
    def ValidateKey(enc):
        code: int = int(0)
        d_0_ok_: bool
        d_1_pt_: Point
        out0_: bool
        out1_: Point
        out0_, out1_ = default__.DecodePoint(enc)
        d_0_ok_ = out0_
        d_1_pt_ = out1_
        if not(d_0_ok_):
            code = 1
            return code
        d_2_small_: bool
        out2_: bool
        out2_ = default__.IsSmallOrder(d_1_pt_)
        d_2_small_ = out2_
        if d_2_small_:
            code = 1
            return code
        code = 0
        return code

    @staticmethod
    def VerifyStrict(Aenc, sig, m):
        code: int = int(0)
        if (len(sig)) != (64):
            code = 1
            return code
        d_0_Renc_: _dafny.Seq
        d_0_Renc_ = _dafny.SeqWithoutIsStrInference((sig)[0:32:])
        d_1_S_: int
        d_1_S_ = default__.LEInt(sig, 32, 32)
        if (d_1_S_) >= (default__.L):
            code = 1
            return code
        d_2_okR_: bool
        d_3_R_: Point
        out0_: bool
        out1_: Point
        out0_, out1_ = default__.DecodePoint(d_0_Renc_)
        d_2_okR_ = out0_
        d_3_R_ = out1_
        if not(d_2_okR_):
            code = 1
            return code
        d_4_okA_: bool
        d_5_A_: Point
        out2_: bool
        out3_: Point
        out2_, out3_ = default__.DecodePoint(Aenc)
        d_4_okA_ = out2_
        d_5_A_ = out3_
        if not(d_4_okA_):
            code = 1
            return code
        d_6_smallR_: bool
        out4_: bool
        out4_ = default__.IsSmallOrder(d_3_R_)
        d_6_smallR_ = out4_
        if d_6_smallR_:
            code = 1
            return code
        d_7_hin_: _dafny.Seq
        d_7_hin_ = ((d_0_Renc_) + (Aenc)) + (m)
        d_8_hk_: _dafny.Seq
        out5_: _dafny.Seq
        out5_ = Sha.default__.Sha512(d_7_hin_)
        d_8_hk_ = out5_
        d_9_kfull_: int
        d_9_kfull_ = default__.LEInt(d_8_hk_, 0, 64)
        d_10_k_: int
        d_10_k_ = _dafny.euclidian_modulus(d_9_kfull_, default__.L)
        d_11_B_: Point
        d_11_B_ = Point_Pt(default__.BX, default__.BY)
        d_12_left_: Point
        out6_: Point
        out6_ = default__.ScalarMul(d_1_S_, d_11_B_)
        d_12_left_ = out6_
        d_13_kA_: Point
        out7_: Point
        out7_ = default__.ScalarMul(d_10_k_, d_5_A_)
        d_13_kA_ = out7_
        d_14_right_: Point
        out8_: Point
        out8_ = default__.PAdd(d_3_R_, d_13_kA_)
        d_14_right_ = out8_
        if default__.PEq(d_12_left_, d_14_right_):
            code = 0
        elif True:
            code = 1
        return code

    @_dafny.classproperty
    def P(instance):
        return 57896044618658097711785492504343953926634992332820282019728792003956564819949
    @_dafny.classproperty
    def D(instance):
        return 37095705934669439343138083508754565189542113879843219016388785533085940283555
    @_dafny.classproperty
    def IDENT(instance):
        return Point_Pt(0, 1)
    @_dafny.classproperty
    def SQRTM1(instance):
        return 19681161376707505956807079304988542015446066515923890162744021073123829784752
    @_dafny.classproperty
    def L(instance):
        return 7237005577332262213973186563042994240857116359379907606001950938285454250989
    @_dafny.classproperty
    def BX(instance):
        return 15112221349535400772501151409588531511454012693041857206046113283949847762202
    @_dafny.classproperty
    def BY(instance):
        return 46316835694926478169428394003475163141307993866256225615783033603165251855960

class Point:
    @classmethod
    def default(cls, ):
        return lambda: Point_Pt(int(0), int(0))
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Pt(self) -> bool:
        return isinstance(self, Point_Pt)

class Point_Pt(Point, NamedTuple('Pt', [('x', Any), ('y', Any)])):
    def __dafnystr__(self) -> str:
        return f'Ed.Point.Pt({_dafny.string_of(self.x)}, {_dafny.string_of(self.y)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Point_Pt) and self.x == __o.x and self.y == __o.y
    def __hash__(self) -> int:
        return super().__hash__()

