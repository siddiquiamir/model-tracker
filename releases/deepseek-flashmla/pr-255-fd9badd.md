# DeepSeek FlashMLA — pr-255-fd9badd

- **Track:** `deepseek:flashmla`
- **Version:** `pr-255-fd9badd`
- **Published:** 2026-11-26T09:46:33Z
- **Captured (UTC):** 2026-11-27T19:44:40Z
- **Total bullet items:** 65
- **Source:** https://github.com/deepseek-ai/FlashMLA/pull/255
- **Capability tags:** `hooks`

## Ready-to-Post Tweet

```text
DeepSeek FlashMLA pr-255-fd9badd is out (65 changes) 🚀

Add Fused Kernel and head128 Support for Ascend, and Optimize the Ascend Sparse Kernels
• Add the fused norm+RoPE+attention+RoPE+cast kernel for the…
• Add head128 (h_q = 128) support for the Ascend prefill and…
```

## Buried Gems & Power-User Signals

- **Hooks & Config Keys:** `setup.py`

## Complete Verbatim Release Notes (Nothing Omitted)

**Commit:** `fd9badd` · **Headline:** Add Fused Kernel and head128 Support for Ascend, and Optimize the Ascend Sparse Kernels
**Diff stats:** `+2186 / -1511` across `61` files (PR #255)

### PR Description

- Add the fused norm+RoPE+attention+RoPE+cast kernel for the Huawei Ascend 950 NPU (by @interestingLSY <shengyuliu@deepseek.com>)
- Add head128 (h_q = 128) support for the Ascend prefill and decoding kernels (by @positivefirst <positive1@deepseek.com>)
- Performance optimization for Ascend prefill & decoding kernels (by @positivefirst <positive1@deepseek.com>, @interestingLSY <shengyuliu@deepseek.com>))
- Some small tweaks for NVIDIA kernels (by @interestingLSY <shengyuliu@deepseek.com>)

Co-authored-by: @interestingLSY <shengyuliu@deepseek.com>
Co-authored-by: @positivefirst <positive1@deepseek.com>

### Changed Files (61 listed)

- `modified` (`+11/-5`) `README.md`
- `modified` (`+237/-17`) `csrc/api/fused_norm_rope_attn_rope_cast_fwd.cpp`
- `modified` (`+15/-10`) `csrc/api/sparse_decode.cpp`
- `modified` (`+19/-38`) `csrc/api/sparse_prefill.cpp`
- `modified` (`+120/-34`) `csrc/ascend_kernels/prefill/sparse/config.h`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h128_decode_nosink.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h128_decode_nosink_nonorm.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h128_decode_nosink_norm.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h128_decode_sink.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h128_decode_sink_nonorm.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h128_decode_sink_norm.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h128_prefill_nosink.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h128_prefill_nosink_nonorm.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h128_prefill_nosink_norm.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h128_prefill_sink.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h128_prefill_sink_nonorm.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h128_prefill_sink_norm.asc`
- `modified` (`+1/-1`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h64_decode_nosink.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h64_decode_nosink_nonorm.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h64_decode_nosink_norm.asc`
- `modified` (`+1/-1`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h64_decode_sink.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h64_decode_sink_nonorm.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h64_decode_sink_norm.asc`
- `modified` (`+1/-1`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h64_prefill_nosink.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h64_prefill_nosink_nonorm.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h64_prefill_nosink_norm.asc`
- `modified` (`+1/-1`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h64_prefill_sink.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h64_prefill_sink_nonorm.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41_h64_prefill_sink_norm.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41fp4_h128_decode_nosink.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41fp4_h128_decode_nosink_nonorm.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41fp4_h128_decode_nosink_norm.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41fp4_h128_decode_sink.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41fp4_h128_decode_sink_nonorm.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41fp4_h128_decode_sink_norm.asc`
- `modified` (`+1/-1`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41fp4_h64_decode_nosink.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41fp4_h64_decode_nosink_nonorm.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41fp4_h64_decode_nosink_norm.asc`
- `modified` (`+1/-1`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41fp4_h64_decode_sink.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41fp4_h64_decode_sink_nonorm.asc`
- `added` (`+9/-0`) `csrc/ascend_kernels/prefill/sparse/instantiations/v41fp4_h64_decode_sink_norm.asc`
- `modified` (`+17/-3`) `csrc/ascend_kernels/prefill/sparse/kernel.h`
- `modified` (`+1082/-300`) `csrc/ascend_kernels/prefill/sparse/kernel_body.h`
- `modified` (`+18/-4`) `csrc/cuda_kernels/sm100/common_subroutine.h`
- `modified` (`+2/-0`) `csrc/cuda_kernels/sm100/decode/sparse/head64/kernel.cuh`
- `modified` (`+16/-0`) `csrc/cuda_kernels/sm100/helpers.h`
- `modified` (`+1/-1`) `csrc/cuda_kernels/sm100/prefill/sparse/fused_norm_rope_attn_rope_cast_fwd/core_attn/kernel.cuh`
- `removed` (`+0/-135`) `csrc/cuda_kernels/sm100/prefill/sparse/fwd/head128/config.h`
- `removed` (`+0/-2`) `csrc/cuda_kernels/sm100/prefill/sparse/fwd/head128/instantiations/phase1_k512.cu`
- `removed` (`+0/-711`) `csrc/cuda_kernels/sm100/prefill/sparse/fwd/head128/phase1.cuh`
- `removed` (`+0/-10`) `csrc/cuda_kernels/sm100/prefill/sparse/fwd/head128/phase1.h`
- `modified` (`+1/-4`) `csrc/cuda_kernels/sm100/prefill/sparse/fwd/head64/config.h`
- `modified` (`+51/-51`) `csrc/cuda_kernels/sm100/prefill/sparse/fwd/head64/phase1.cuh`
- `modified` (`+3/-3`) `csrc/cuda_kernels/sm100/prefill/sparse/fwd_for_small_topk/head128/config.h`
- `modified` (`+13/-10`) `csrc/cuda_kernels/sm100/prefill/sparse/fwd_for_small_topk/head128/phase1.cuh`
- `modified` (`+36/-0`) `csrc/params.h`
- `modified` (`+6/-2`) `flash_mla/fused_norm_rope_attn_rope_cast.py`
- `modified` (`+49/-33`) `scripts/generate_instantiations.py`
- `modified` (`+11/-11`) `setup.py`
- `modified` (`+22/-2`) `tests/lib.py`
- `modified` (`+180/-119`) `tests/test-fused-norm-rope-attn-rope-cast.py`
