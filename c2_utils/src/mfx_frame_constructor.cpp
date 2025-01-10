// Copyright (c) 2017-2022 Intel Corporation
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "mfx_frame_constructor.h"
#include "mfx_debug.h"
#include "mfx_msdk_debug.h"
#include "mfx_c2_bs_utils.h"
#include "mfx_c2_hevc_bitstream.h"
#include "mfx_c2_utils.h"

#undef MFX_DEBUG_MODULE_NAME
#define MFX_DEBUG_MODULE_NAME "mfx_frame_constructor"

const std::vector<mfxU32> MfxC2HEVCFrameConstructor::NAL_UT_CODED_SLICEs = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 17, 18, 19, 20, 21 };

MfxC2FrameConstructor::MfxC2FrameConstructor():
    m_bsState(MfxC2BS_HeaderAwaiting),
    m_profile(MFX_PROFILE_UNKNOWN),
    m_bEos(false),
    m_uBstBufReallocs(0),
    m_uBstBufCopyBytes(0),
    m_bInReset(false)
{
    MFX_DEBUG_TRACE_FUNC;

    m_bstHeader = std::make_shared<mfxBitstream>();
    m_bstBuf = std::make_shared<mfxBitstream>();
    m_bstIn = std::make_shared<mfxBitstream>();

    MFX_ZERO_MEMORY((*m_bstHeader));
    MFX_ZERO_MEMORY((*m_bstBuf));
    MFX_ZERO_MEMORY((*m_bstIn));
    MFX_ZERO_MEMORY(m_frInfo);
}

MfxC2FrameConstructor::~MfxC2FrameConstructor()
{
    MFX_DEBUG_TRACE_FUNC;

    if (m_bstBuf->Data) {
        MFX_DEBUG_TRACE_I32(m_bstBuf->MaxLength);
        MFX_DEBUG_TRACE_I32(m_uBstBufReallocs);
        MFX_DEBUG_TRACE_I32(m_uBstBufCopyBytes);

        MFX_FREE(m_bstBuf->Data);
    }

    MFX_FREE(m_bstHeader->Data);
}

mfxStatus MfxC2FrameConstructor::Init(
    mfxU16 profile,
    mfxFrameInfo fr_info )
{
    MFX_DEBUG_TRACE_FUNC;
    mfxStatus mfx_res = MFX_ERR_NONE;

    m_profile = profile;
    m_frInfo = fr_info;
    MFX_DEBUG_TRACE__mfxStatus(mfx_res);
    return mfx_res;
}

mfxStatus MfxC2FrameConstructor::LoadHeader(const mfxU8* data, mfxU32 size, bool header)
{
    MFX_DEBUG_TRACE_FUNC;
    mfxStatus mfx_res = MFX_ERR_NONE;

    MFX_DEBUG_TRACE_P(data);
    MFX_DEBUG_TRACE_I32(size);
    MFX_DEBUG_TRACE_I32(header);
    MFX_DEBUG_TRACE_I32(m_bsState);
    if (!data || !size) mfx_res = MFX_ERR_NULL_PTR;
    if (MFX_ERR_NONE == mfx_res) {
        if (header) {
            // if new header arrived after reset we are ignoring previously collected header data
            if (m_bsState == MfxC2BS_Resetting) {
                m_bsState = MfxC2BS_HeaderObtained;
            } else if (size) {
                mfxU32 needed_MaxLength = 0;
                mfxU8* new_data = nullptr;

                needed_MaxLength = m_bstHeader->DataOffset + m_bstHeader->DataLength + size; // offset should be 0
                if (m_bstHeader->MaxLength < needed_MaxLength) {
                    // increasing buffer capacity if needed
                    new_data = (mfxU8*)realloc(m_bstHeader->Data, needed_MaxLength);
                    if (new_data) {
                        // setting new values
                        m_bstHeader->Data = new_data;
                        m_bstHeader->MaxLength = needed_MaxLength;
                    }
                    else mfx_res = MFX_ERR_MEMORY_ALLOC;
                }
                if (MFX_ERR_NONE == mfx_res) {
                    mfxU8* buf = m_bstHeader->Data + m_bstHeader->DataOffset + m_bstHeader->DataLength;

                    std::copy(data, data + size, buf);
                    m_bstHeader->DataLength += size;
                }
                if (MfxC2BS_HeaderAwaiting == m_bsState) m_bsState = MfxC2BS_HeaderCollecting;
            }
        } else {
            // We have generic data. In case we are in Resetting state (i.e. seek mode)
            // we attach header to the bitstream, other wise we are moving in Obtained state.
            if (MfxC2BS_HeaderCollecting == m_bsState) {
                // As soon as we are receving first non header data we are stopping collecting header
                m_bsState = MfxC2BS_HeaderObtained;
            }
            else if (MfxC2BS_Resetting == m_bsState) {
                // if reset detected and we have header data buffered - we are going to load it
                mfx_res = BstBufRealloc(m_bstHeader->DataLength);
                if (MFX_ERR_NONE == mfx_res) {
                    mfxU8* buf = m_bstBuf->Data + m_bstBuf->DataOffset + m_bstBuf->DataLength;

                    std::copy(m_bstHeader->Data + m_bstHeader->DataOffset,
                        m_bstHeader->Data + m_bstHeader->DataOffset + m_bstHeader->DataLength, buf);
                    m_bstBuf->DataLength += m_bstHeader->DataLength;
                    m_uBstBufCopyBytes += m_bstHeader->DataLength;
                }
                m_bsState = MfxC2BS_HeaderObtained;
            }
        }
    }
    MFX_DEBUG_TRACE__mfxStatus(mfx_res);
    return mfx_res;
}

mfxStatus MfxC2FrameConstructor::Load_None(const mfxU8* data, mfxU32 size, mfxU64 pts, bool header, bool complete_frame)
{
    MFX_DEBUG_TRACE_FUNC;
    mfxStatus mfx_res = MFX_ERR_NONE;

    mfx_res = LoadHeader(data, size, header);
    if ((MFX_ERR_NONE == mfx_res) && m_bstBuf->DataLength) {
        mfx_res = BstBufRealloc(size);
        if (MFX_ERR_NONE == mfx_res) {
            mfxU8* buf = m_bstBuf->Data + m_bstBuf->DataOffset + m_bstBuf->DataLength;

            std::copy(data, data + size, buf);
            m_bstBuf->DataLength += size;
            m_uBstBufCopyBytes += size;
        }
    }
    if (MFX_ERR_NONE == mfx_res) {
        if (m_bstBuf->DataLength) m_bstCurrent = m_bstBuf;
        else {
            m_bstIn->Data = (mfxU8*)data;
            m_bstIn->DataOffset = 0;
            m_bstIn->DataLength = size;
            m_bstIn->MaxLength = size;
            if (complete_frame)
                m_bstIn->DataFlag |= MFX_BITSTREAM_COMPLETE_FRAME;

            m_bstCurrent = m_bstIn;
        }
        m_bstCurrent->TimeStamp = pts;
    }
    else m_bstCurrent = nullptr;
    MFX_DEBUG_TRACE__mfxStatus(mfx_res);
    return mfx_res;
}

mfxStatus MfxC2FrameConstructor::Load(const mfxU8* data, mfxU32 size, mfxU64 pts, bool header, bool complete_frame)
{
    MFX_DEBUG_TRACE_FUNC;
    mfxStatus mfx_res = MFX_ERR_NONE;

    MFX_DEBUG_TRACE_P(data);
    MFX_DEBUG_TRACE_I32(size);
    MFX_DEBUG_TRACE_I64(pts);
    if (!data || !size) mfx_res = MFX_ERR_NULL_PTR;
    if (MFX_ERR_NONE == mfx_res) {
        mfx_res = Load_None(data, size, pts, header, complete_frame);
    }
    MFX_DEBUG_TRACE__mfxBitstream((*m_bstBuf));
    MFX_DEBUG_TRACE__mfxBitstream((*m_bstIn));
    MFX_DEBUG_TRACE__mfxStatus(mfx_res);
    return mfx_res;
}

mfxStatus MfxC2FrameConstructor::Unload()
{
    MFX_DEBUG_TRACE_FUNC;
    mfxStatus mfx_res = MFX_ERR_NONE;

    if(m_bInReset) {
        m_bInReset = false;
    }

    mfx_res = BstBufSync();

    MFX_DEBUG_TRACE__mfxStatus(mfx_res);
    return mfx_res;
}

// NOTE: we suppose that Load/Unload were finished
mfxStatus MfxC2FrameConstructor::Reset()
{
    MFX_DEBUG_TRACE_FUNC;
    mfxStatus mfx_res = MFX_ERR_NONE;

    m_bInReset = true;

    // saving allocating information about internal buffer
    mfxU8* data = m_bstBuf->Data;
    mfxU32 allocated_length = m_bstBuf->MaxLength;

    // resetting frame constructor
    m_bstCurrent = nullptr;
    m_bstBuf = std::make_shared<mfxBitstream>();
    MFX_ZERO_MEMORY((*m_bstBuf));
    m_bstIn = std::make_shared<mfxBitstream>();
    MFX_ZERO_MEMORY((*m_bstIn));

    m_bEos = false;

    // restoring allocating information about internal buffer
    m_bstBuf->Data = data;
    m_bstBuf->MaxLength = allocated_length;

    // we have some header data and will attempt to return it
    if (m_bsState >= MfxC2BS_HeaderCollecting) m_bsState = MfxC2BS_Resetting;

    MFX_DEBUG_TRACE__mfxStatus(mfx_res);
    return mfx_res;
}

bool MfxC2FrameConstructor::IsInReset()
{
    return m_bInReset;
}

mfxStatus MfxC2FrameConstructor::BstBufRealloc(mfxU32 add_size)
{
    MFX_DEBUG_TRACE_FUNC;
    mfxStatus mfx_res = MFX_ERR_NONE;
    mfxU32 needed_MaxLength = 0;
    mfxU8* new_data = nullptr;

    if (add_size) {
        needed_MaxLength = m_bstBuf->DataOffset + m_bstBuf->DataLength + add_size; // offset should be 0
        if (m_bstBuf->MaxLength < needed_MaxLength) {
            // increasing buffer capacity if needed
            new_data = (mfxU8*)realloc(m_bstBuf->Data, needed_MaxLength);
            if (new_data) {
                // collecting statistics
                ++m_uBstBufReallocs;
                if (new_data != m_bstBuf->Data) m_uBstBufCopyBytes += m_bstBuf->MaxLength;
                // setting new values
                m_bstBuf->Data = new_data;
                m_bstBuf->MaxLength = needed_MaxLength;
            }
            else mfx_res = MFX_ERR_MEMORY_ALLOC;
        }
    }
    MFX_DEBUG_TRACE__mfxStatus(mfx_res);
    return mfx_res;
}

mfxStatus MfxC2FrameConstructor::BstBufMalloc(mfxU32 new_size)
{
    MFX_DEBUG_TRACE_FUNC;
    mfxStatus mfx_res = MFX_ERR_NONE;
    mfxU32 needed_MaxLength = 0;

    if (new_size) {
        needed_MaxLength = new_size;
        if (m_bstBuf->MaxLength < needed_MaxLength) {
            // increasing buffer capacity if needed
            MFX_FREE(m_bstBuf->Data);
            m_bstBuf->Data = (mfxU8*)malloc(needed_MaxLength);
            m_bstBuf->MaxLength = needed_MaxLength;
            ++m_uBstBufReallocs;
        }
        if (!(m_bstBuf->Data)) {
            m_bstBuf->MaxLength = 0;
            mfx_res = MFX_ERR_MEMORY_ALLOC;
        }
    }
    MFX_DEBUG_TRACE__mfxStatus(mfx_res);
    return mfx_res;
}

mfxStatus MfxC2FrameConstructor::BstBufSync()
{
    MFX_DEBUG_TRACE_FUNC;
    mfxStatus mfx_res = MFX_ERR_NONE;

    if (nullptr != m_bstCurrent) {
        if (m_bstCurrent == m_bstBuf) {
            if (m_bstBuf->DataLength && m_bstBuf->DataOffset) {
                // shifting data to the beginning of the buffer
                memmove(m_bstBuf->Data, m_bstBuf->Data + m_bstBuf->DataOffset, m_bstBuf->DataLength);
                m_uBstBufCopyBytes += m_bstBuf->DataLength;
            }
            m_bstBuf->DataOffset = 0;
        }
        if ((m_bstCurrent == m_bstIn) && m_bstIn->DataLength) {
            // copying data from m_bstIn to bst_Buf
            // Note: we read data from m_bstIn, thus here bst_Buf is empty
            mfx_res = BstBufMalloc(m_bstIn->DataLength);
            if (MFX_ERR_NONE == mfx_res) {
                std::copy(m_bstIn->Data + m_bstIn->DataOffset,
                    m_bstIn->Data + m_bstIn->DataOffset + m_bstIn->DataLength, m_bstBuf->Data);
                m_bstBuf->DataOffset = 0;
                m_bstBuf->DataLength = m_bstIn->DataLength;
                m_bstBuf->TimeStamp  = m_bstIn->TimeStamp;
                m_bstBuf->DataFlag   = m_bstIn->DataFlag;
                m_uBstBufCopyBytes += m_bstIn->DataLength;
            }
            m_bstIn = std::make_shared<mfxBitstream>();
            MFX_ZERO_MEMORY((*m_bstIn));
        }
        m_bstCurrent = nullptr;
    }
    MFX_DEBUG_TRACE__mfxStatus(mfx_res);
    return mfx_res;
}

std::shared_ptr<mfxBitstream> MfxC2FrameConstructor::GetMfxBitstream()
{
    MFX_DEBUG_TRACE_FUNC;

    std::shared_ptr<mfxBitstream> bst;

    if (m_bstBuf->Data && m_bstBuf->DataLength) {
        bst = m_bstBuf;
    } else if (m_bstIn->Data && m_bstIn->DataLength) {
        bst = m_bstIn;
    } else {
        bst = m_bstBuf;
    }

    MFX_DEBUG_TRACE_P(m_bstIn.get());
    MFX_DEBUG_TRACE_P(m_bstBuf.get());
    MFX_DEBUG_TRACE_P(bst.get());

    return bst;
}

mfxStatus MfxC2FrameConstructor::Load_data(const mfxU8* data, mfxU32 size, const mfxU8* bs, mfxU64 pts, bool b_header, bool bComplete)
{
    MFX_DEBUG_TRACE_FUNC;
    return MFX_ERR_NONE;
}

MfxC2AVCFrameConstructor::MfxC2AVCFrameConstructor():
    MfxC2FrameConstructor()
{
    MFX_DEBUG_TRACE_FUNC;

    MFX_ZERO_MEMORY(m_sps);
    MFX_ZERO_MEMORY(m_pps);
}

MfxC2AVCFrameConstructor::~MfxC2AVCFrameConstructor()
{
    MFX_DEBUG_TRACE_FUNC;

    MFX_FREE(m_sps.Data);
    MFX_FREE(m_pps.Data);
}

mfxStatus MfxC2AVCFrameConstructor::SaveHeaders(std::shared_ptr<mfxBitstream> sps, std::shared_ptr<mfxBitstream> pps, bool is_reset)
{
    MFX_DEBUG_TRACE_FUNC;

    if (is_reset) Reset();

    if (nullptr != sps) {
        if (m_sps.MaxLength < sps->DataLength) {
            m_sps.Data = (mfxU8*)realloc(m_sps.Data, sps->DataLength);
            if (!m_sps.Data)
                return MFX_ERR_MEMORY_ALLOC;
            m_sps.MaxLength = sps->DataLength;
        }
        std::copy(sps->Data + sps->DataOffset,
            sps->Data + sps->DataOffset + sps->DataLength, m_sps.Data);
        m_sps.DataLength = sps->DataLength;
    }
    if (nullptr != pps) {
        if (m_pps.MaxLength < pps->DataLength) {
            m_pps.Data = (mfxU8*)realloc(m_pps.Data, pps->DataLength);
            if (!m_pps.Data)
                return MFX_ERR_MEMORY_ALLOC;
            m_pps.MaxLength = pps->DataLength;
        }
        std::copy(pps->Data + pps->DataOffset, pps->Data + pps->DataOffset + pps->DataLength, m_pps.Data);
        m_pps.DataLength = pps->DataLength;
    }
    return MFX_ERR_NONE;
}

mfxStatus MfxC2AVCFrameConstructor::FindHeaders(const mfxU8* data, mfxU32 size, bool &found_sps, bool &found_pps, bool &found_sei)
{
    MFX_DEBUG_TRACE_FUNC;
    mfxStatus mfx_res = MFX_ERR_NONE;

    found_sps = false;
    found_pps = false;
    found_sei = false;

    if (data && size) {
        StartCode start_code;
        mfxU32 length;
        for (; size > 3;) {
            start_code = ReadStartCode(&data, &size);
            if (isSPS(start_code.type)) {
                std::shared_ptr<mfxBitstream> sps = std::make_shared<mfxBitstream>();

                MFX_ZERO_MEMORY((*sps));
                sps->Data = (mfxU8*)data - start_code.size;

                length = size + start_code.size;
                start_code = ReadStartCode(&data, &size);
                if (-1 != start_code.type)
                    length -= size + start_code.size;
                sps->DataLength = length;
                MFX_DEBUG_TRACE_STREAM("Found SPS size " << length);
                mfx_res = SaveHeaders(std::move(sps), nullptr, false);
                if (MFX_ERR_NONE != mfx_res) return mfx_res;
                found_sps = true;
            }
            if (isPPS(start_code.type)) {
                std::shared_ptr<mfxBitstream> pps = std::make_shared<mfxBitstream>();

                MFX_ZERO_MEMORY((*pps));
                pps->Data = (mfxU8*)data - start_code.size;

                length = size + start_code.size;
                start_code = ReadStartCode(&data, &size);
                if (-1 != start_code.type)
                    length -= size + start_code.size;
                pps->DataLength = length;
                MFX_DEBUG_TRACE_STREAM("Found PPS size " << length);
                mfx_res = SaveHeaders(nullptr, std::move(pps), false);
                if (MFX_ERR_NONE != mfx_res) return mfx_res;
                found_pps = true;
            }
            if (isIDR(start_code.type)) {
                MFX_DEBUG_TRACE_STREAM("Found IDR ");
            }
            while (isSEI(start_code.type))
            {
                mfxBitstream sei = {};
                MFX_ZERO_MEMORY(sei);
                sei.Data = (mfxU8*)data - start_code.size;
                sei.DataLength = size + start_code.size;
                start_code = ReadStartCode(&data, &size);
                if (-1 != start_code.type)
                    sei.DataLength -= size + start_code.size;
                 MFX_DEBUG_TRACE_STREAM("Found SEI size " << sei.DataLength);
                 mfx_res = SaveSEI(&sei);
                 if (MFX_ERR_NONE != mfx_res) return mfx_res;
                 found_sei = true;
             }
            // start code == coded slice, so no need wait SEI
            if (!needWaitSEI(start_code.type)) found_sei = true;
            if (-1 == start_code.type) break;
        }
    }

    MFX_DEBUG_TRACE__mfxStatus(mfx_res);
    return mfx_res;
}

mfxStatus MfxC2AVCFrameConstructor::LoadHeader(const mfxU8* data, mfxU32 size, bool header)
{
    MFX_DEBUG_TRACE_FUNC;
    mfxStatus mfx_res = MFX_ERR_NONE;

    MFX_DEBUG_TRACE_P(data);
    MFX_DEBUG_TRACE_I32(size);
    MFX_DEBUG_TRACE_I32(header);
    MFX_DEBUG_TRACE_I32(m_bsState);

    bool bFoundSps = false;
    bool bFoundPps = false;
    bool bFoundSei = false;

    if (header && data && size) {
        if (MfxC2BS_HeaderAwaiting == m_bsState) m_bsState = MfxC2BS_HeaderCollecting;

        mfx_res = FindHeaders(data, size, bFoundSps, bFoundPps, bFoundSei);
        if (MFX_ERR_NONE == mfx_res && bFoundSps && bFoundPps)
            m_bsState = bFoundSei ? MfxC2BS_HeaderObtained : MfxC2BS_HeaderWaitSei;

    } else if (MfxC2BS_Resetting == m_bsState) {
        mfx_res = FindHeaders(data, size, bFoundSps, bFoundPps, bFoundSei);
        if (MFX_ERR_NONE == mfx_res) {
            if (!bFoundSps || !bFoundPps) {
                // In case we are in Resetting state (i.e. seek mode)
                // and bitstream has no headers, we attach header to the bitstream.
                mfx_res = BstBufRealloc(m_sps.DataLength + m_pps.DataLength);
                if (MFX_ERR_NONE == mfx_res) {
                    mfxU8* buf = m_bstBuf->Data + m_bstBuf->DataOffset + m_bstBuf->DataLength;
                    std::copy(m_sps.Data, m_sps.Data + m_sps.DataLength, buf);
                    buf += m_sps.DataLength;
                    std::copy(m_pps.Data, m_pps.Data + m_pps.DataLength, buf);

                    m_bstBuf->DataLength += m_sps.DataLength + m_pps.DataLength;
                    m_uBstBufCopyBytes += m_sps.DataLength + m_pps.DataLength;
                }
            }
            m_bsState = MfxC2BS_HeaderObtained;
        }
    } else if (MfxC2BS_HeaderCollecting == m_bsState) {
        // As soon as we are receving first non header data we are stopping collecting header
        m_bsState = MfxC2BS_HeaderObtained;
    } else if (MfxC2BS_HeaderWaitSei == m_bsState) {
        mfx_res = FindHeaders(data, size, bFoundSps, bFoundPps, bFoundSei);
        if (MFX_ERR_NONE == mfx_res && bFoundSps && bFoundPps)
        {
            m_bsState = bFoundSei ? MfxC2BS_HeaderObtained : MfxC2BS_HeaderWaitSei;
        }
    }

    MFX_DEBUG_TRACE__mfxStatus(mfx_res);
    return mfx_res;
}

IMfxC2FrameConstructor::StartCode MfxC2AVCFrameConstructor::ReadStartCode(const mfxU8** position, mfxU32* size_left)
{
    MFX_DEBUG_TRACE_FUNC;

    StartCode start_code = { .type=-1, .size=0 };
    mfxU32 zero_count = 0;
    static const mfxU8 nal_unit_type_bits = 0x1f;

    mfxI32 i = 0;
    for (; i < (mfxI32)*size_left - 2; ) {
        if ((*position)[1]) {
            *position += 2;
            i += 2;
            continue;
        }

        zero_count = 0;
        if (!(*position)[0]) zero_count++;

        mfxU32 j;
        for (j = 1; j < (mfxU32)*size_left - i; j++) {
            if ((*position)[j]) break;
        }

        zero_count = zero_count ? j: j - 1;

        *position += j;
        i += j;

        if (i >= (mfxI32)*size_left) break;

        if (zero_count >= 2 && (*position)[0] == 1) {
            start_code.size = MFX_MIN(zero_count + 1, 4);
            *size_left -= i + 1;
            (*position)++; // remove 0x01 symbol
            if (*size_left >= 1) {
                start_code.type = (*position)[0] & nal_unit_type_bits;
            } else {
                *position -= start_code.size;
                *size_left += start_code.size;
                start_code.size = 0;
            }
            return start_code;
        }
        zero_count = 0;
    }

    if (!zero_count) {
        for (mfxU32 k = 0; k < *size_left - i; k++, (*position)++) {
            if ((*position)[0]) {
                zero_count = 0;
                continue;
            }
            zero_count++;
        }
    }

    zero_count = MFX_MIN(zero_count, 3);
    *position -= zero_count;
    *size_left = zero_count;
    return start_code;
}

mfxStatus MfxC2AVCFrameConstructor::Load(const mfxU8* data, mfxU32 size, mfxU64 pts, bool header, bool complete_frame)
{
    MFX_DEBUG_TRACE_FUNC;
    mfxStatus mfx_res = MFX_ERR_NONE;

    mfx_res = MfxC2FrameConstructor::Load(data, size, pts, header, complete_frame);

    MFX_DEBUG_TRACE__mfxStatus(mfx_res);
    return mfx_res;
}

mfxStatus MfxC2AVCFrameConstructor::Load_data(const mfxU8* data, mfxU32 size, const mfxU8* bs, mfxU64 pts, bool b_header, bool bComplete)
{
    MFX_DEBUG_TRACE_FUNC;
    return MFX_ERR_NONE;
}

MfxC2HEVCFrameConstructor::MfxC2HEVCFrameConstructor():
    MfxC2AVCFrameConstructor()
{
    MFX_DEBUG_TRACE_FUNC;
}

MfxC2HEVCFrameConstructor::~MfxC2HEVCFrameConstructor()
{
    MFX_DEBUG_TRACE_FUNC;
}

IMfxC2FrameConstructor::StartCode MfxC2HEVCFrameConstructor::ReadStartCode(const mfxU8** position, mfxU32* size_left)
{
    MFX_DEBUG_TRACE_FUNC;

    StartCode start_code = { .type=-1, .size=0 };
    mfxU32 zero_count = 0;
    static const mfxU8 NAL_UNITTYPE_BITS_H265 = 0x7e;
    static const mfxU8 NAL_UNITTYPE_SHIFT_H265 = 1;

    mfxI32 i = 0;
    for (; i < (mfxI32)*size_left - 2; ) {
        if ((*position)[1]) {
            *position += 2;
            i += 2;
            continue;
        }

        zero_count = 0;
        if (!(*position)[0]) zero_count++;

        mfxU32 j;
        for (j = 1; j < (mfxU32)*size_left - i; j++) {
            if ((*position)[j]) break;
        }

        zero_count = zero_count ? j: j - 1;

        *position += j;
        i += j;

        if (i >= (mfxI32)*size_left) break;

        if (zero_count >= 2 && (*position)[0] == 1) {
            start_code.size = MFX_MIN(zero_count + 1, 4);
            *size_left -= i + 1;
            (*position)++; // remove 0x01 symbol
            if (*size_left >= 1) {
                start_code.type = ((*position)[0] & NAL_UNITTYPE_BITS_H265) >> NAL_UNITTYPE_SHIFT_H265;
            } else {
                *position -= start_code.size;
                *size_left += start_code.size;
                start_code.size = 0;
            }
            return start_code;
        }
        zero_count = 0;
    }

    if (!zero_count) {
        for (mfxU32 k = 0; k < *size_left - i; k++, (*position)++) {
            if ((*position)[0]) {
                zero_count = 0;
                continue;
            }
            zero_count++;
        }
    }

    zero_count = MFX_MIN(zero_count, 3);
    *position -= zero_count;
    *size_left = zero_count;
    return start_code;
}

mfxStatus MfxC2HEVCFrameConstructor::SaveSEI(mfxBitstream *pSEI)
{
    MFX_DEBUG_TRACE_FUNC;
    mfxStatus mfx_res = MFX_ERR_NONE;

    if (nullptr != pSEI && nullptr != pSEI->Data)
    {
        std::vector<mfxU8> swappingMemory;
        mfxU32 swappingMemorySize = pSEI->DataLength - 5;
        swappingMemory.resize(swappingMemorySize + 8);

        std::vector<mfxU32> SEINames = {SEI_MASTERING_DISPLAY_COLOUR_VOLUME, SEI_CONTENT_LIGHT_LEVEL_INFO};
        for (auto const& sei_name : SEINames) // look for sei
        {
            mfxPayload sei = {};
            sei.BufSize = pSEI->DataLength;
            sei.Data = (mfxU8*)realloc(sei.Data, pSEI->DataLength);
            if (nullptr == sei.Data)
            {
                MFX_DEBUG_TRACE_MSG("ERROR: SEI was not alloacated");
                return MFX_ERR_MEMORY_ALLOC;
            }

            MFX_DEBUG_TRACE_MSG("Calling ByteSwapper::SwapMemory()");

            BytesSwapper::SwapMemory(&(swappingMemory[0]), swappingMemorySize, (pSEI->Data + 5), swappingMemorySize);

            MFX_DEBUG_TRACE_MSG("Calling HEVCHeadersBitstream.Reset()");
            MFX_DEBUG_TRACE_U32(swappingMemorySize);

            HEVCParser::HEVCHeadersBitstream bitStream;
            bitStream.Reset(&(swappingMemory[0]), swappingMemorySize);

            MFX_DEBUG_TRACE_MSG("Calling HEVCHeadersBitstream.GetSEI() for SEI");
            MFX_DEBUG_TRACE_U32(sei_name);

            MFX_TRY_AND_CATCH(
                bitStream.GetSEI(&sei, sei_name),
                sei.NumBit = 0);
            if (sei.Type == sei_name && sei.NumBit > 0)
            {
                // replace sei
                auto old_sei = m_SEIMap.find(sei_name);
                if (old_sei != m_SEIMap.end())
                {
                    MFX_FREE(old_sei->second.Data);
                    m_SEIMap.erase(old_sei);
                }
                m_SEIMap.insert(std::pair<mfxU32, mfxPayload>(sei_name, sei));
            }
            else
                MFX_FREE(sei.Data);
        }
    }

    MFX_DEBUG_TRACE_I32(mfx_res);
    return mfx_res;
}

mfxPayload* MfxC2HEVCFrameConstructor::GetSEI(mfxU32 type)
{
    auto sei = m_SEIMap.find(type);
    if (sei != m_SEIMap.end())
        return &(sei->second);

    return nullptr;
}

std::shared_ptr<IMfxC2FrameConstructor> MfxC2FrameConstructorFactory::CreateFrameConstructor(MfxC2FrameConstructorType fc_type)
{
    MFX_DEBUG_TRACE_FUNC;

    std::shared_ptr<IMfxC2FrameConstructor> fc;
    if (MfxC2FC_AVC == fc_type) {
        fc = std::make_shared<MfxC2AVCFrameConstructor>();
        return fc;

    } else if (MfxC2FC_HEVC == fc_type) {
        fc = std::make_shared<MfxC2HEVCFrameConstructor>();
        return fc;

    } else if (MfxC2FC_SEC_AVC == fc_type) {
        fc = std::make_shared<MfxC2AVCSecureFrameConstructor>();
        return fc;

    }  else if (MfxC2FC_SEC_HEVC == fc_type) { 
        fc = std::make_shared<MfxC2HEVCSecureFrameConstructor>();
        return fc;
    }

    else {
        fc = std::make_shared<MfxC2FrameConstructor>();
        return fc;
    }
}

MfxC2SecureFrameConstructor::MfxC2SecureFrameConstructor()
{
    MFX_DEBUG_TRACE_FUNC;
    
    m_bstEnc = std::make_shared<mfxBitstream>();

    MFX_ZERO_MEMORY((*m_bstEnc));
}

MfxC2SecureFrameConstructor::~MfxC2SecureFrameConstructor()
{
    MFX_DEBUG_TRACE_FUNC;

    MFX_FREE(m_bstEnc->Data);
}

MfxC2AVCSecureFrameConstructor::MfxC2AVCSecureFrameConstructor() :
    MfxC2HEVCFrameConstructor(), MfxC2SecureFrameConstructor()
{
    MFX_DEBUG_TRACE_FUNC;
}

MfxC2AVCSecureFrameConstructor::~MfxC2AVCSecureFrameConstructor()
{
    MFX_DEBUG_TRACE_FUNC;
}

mfxStatus MfxC2SecureFrameConstructor::Load(const mfxU8* data, mfxU32 size, mfxU64 pts, bool header, bool complete_frame)
{
    MFX_DEBUG_TRACE_FUNC;
    (void)pts;
    (void)header;

    mfxStatus mfx_res = MFX_ERR_NONE;

    if (!data || !size)
    {
        MFX_DEBUG_TRACE_P(data);
        MFX_DEBUG_TRACE_I32(size);
        mfx_res = MFX_ERR_NULL_PTR;
    }

    if (!complete_frame)
        mfx_res = MFX_ERR_UNDEFINED_BEHAVIOR;

    if (MFX_ERR_NONE == mfx_res) {
        HUCVideoBuffer *hucBuffer = NULL;
        hucBuffer = (HUCVideoBuffer *) data;

        if (!hucBuffer)
        {
            MFX_DEBUG_TRACE_P(hucBuffer);
            mfx_res = MFX_ERR_NULL_PTR;
        }
        else m_hucBuffer = hucBuffer;
    }

    MFX_DEBUG_TRACE_I32(mfx_res);
    return mfx_res;
}

mfxStatus MfxC2AVCSecureFrameConstructor::Load(const mfxU8* data, mfxU32 size, mfxU64 pts, bool b_header, bool bCompleteFrame)
{
    MFX_DEBUG_TRACE_FUNC;

    return MfxC2FrameConstructor::Load(data, size, pts, b_header, bCompleteFrame);
}

mfxStatus MfxC2AVCSecureFrameConstructor::Load_data(const mfxU8* data, mfxU32 size, const mfxU8* bs, mfxU64 pts, bool b_header, bool bCompleteFrame)
{
    MFX_DEBUG_TRACE_FUNC;

    mfxStatus mfx_res = MfxC2SecureFrameConstructor::Load(data, size, pts, b_header, bCompleteFrame);
    LoadHeader(bs, m_hucBuffer->sample_size, b_header);

    // if (MFX_ERR_NONE == mfx_res)
    // {
    //     MFX_DEBUG_TRACE_STREAM("m_hucbuffer content:");
    //     MFX_DEBUG_TRACE_I32(pts);
    //     MFX_DEBUG_TRACE_P(bs);
    //     MFX_DEBUG_TRACE_I32(m_hucBuffer->pr_magic);
    //     MFX_DEBUG_TRACE_I32(m_hucBuffer->app_id);
    //     MFX_DEBUG_TRACE_I32(m_hucBuffer->session_id);
    //     MFX_DEBUG_TRACE_I32(m_hucBuffer->num_packet_data);
    //     MFX_DEBUG_TRACE_I32(m_hucBuffer->sample_size);
    //     MFX_DEBUG_TRACE_I32(m_hucBuffer->cipher_mode);
    //     MFX_DEBUG_TRACE_STREAM("hw_key_data = " << FormatHex(m_hucBuffer->hw_key_data, 16).c_str());

    //     for (int i=0; i<m_hucBuffer->num_packet_data; i++)
    //     {
    //         char* baseAddress = reinterpret_cast<char*>(m_hucBuffer);
    //         packet_info* packet = reinterpret_cast<packet_info*>(baseAddress + sizeof(HUCVideoBuffer) - 8 + (i * sizeof(packet_info)));
    //         MFX_DEBUG_TRACE_I32(packet->block_offset);
    //         MFX_DEBUG_TRACE_I32(packet->data_length);
    //         MFX_DEBUG_TRACE_I32(packet->clear_bytes);
    //         MFX_DEBUG_TRACE_I32(packet->encrypted_bytes);
    //         MFX_DEBUG_TRACE_I32(packet->pattern_clear);
    //         MFX_DEBUG_TRACE_I32(packet->pattern_encrypted);
    //         MFX_DEBUG_TRACE_STREAM("iv = " << FormatHex(packet->current_iv.begin(), 16).c_str());
    //     }
    // }

    bool bFoundSps = false;
    bool bFoundPps = false;
    bool bFound_sei = false;
    bool bFoundIDR = false;
    bool bFoundRegularSlice = false;
    char* baseAddress = reinterpret_cast<char*>(m_hucBuffer);
    m_uSpsppssei_size = 0;

    // Save SPS/PPS if exists
    if (MFX_ERR_NONE == mfx_res)
    {
        for(int i = 0; i < m_hucBuffer->num_packet_data; i++)
        {
            data = NULL;
            size = 0;
            packet_info* packet = reinterpret_cast<packet_info*>(baseAddress + sizeof(HUCVideoBuffer) - 8 + (i * sizeof(packet_info)));

            if (packet->clear_bytes != 0)
            {
                data = bs + packet->block_offset;
                size = packet->clear_bytes;
            }
            else
            {
                continue; // All start codes are located in clear packeds, so we don't need to check encrypted packets
            }
            StartCode startCode;
            mfxU32 length;
            for (; size > 3;)
            {
                startCode = ReadStartCode(&data, &size);
                if (isSPS(startCode.type))
                {
                    auto sps = std::make_shared<mfxBitstream>();
                    sps->Data = const_cast<mfxU8*>(data) - startCode.size;

                    length = size + startCode.size;
                    startCode = ReadStartCode(&data, &size);
                    if (-1 != startCode.type)
                        length -= size + startCode.size;
                    sps->DataLength = length;
                    MFX_DEBUG_TRACE_MSG("Found SPS, length =");
                    MFX_DEBUG_TRACE_I32(length);
                    m_uSpsppssei_size += length;
                    mfx_res = SaveHeaders(sps, NULL, false);
                    if (MFX_ERR_NONE != mfx_res) return mfx_res;
                    bFoundSps = true;
                }
                if (isPPS(startCode.type))
                {
                    auto pps = std::make_shared<mfxBitstream>();
                    pps->Data = const_cast<mfxU8*>(data) - startCode.size;

                    length = size + startCode.size;
                    startCode = ReadStartCode(&data, &size);
                    if (-1 != startCode.type)
                        length -= size + startCode.size;
                    pps->DataLength = length;
                    MFX_DEBUG_TRACE_MSG("Found PPS, length =");
                    MFX_DEBUG_TRACE_I32(length);
                    m_uSpsppssei_size += length;
                    mfx_res = SaveHeaders(NULL, pps, false);
                    if (MFX_ERR_NONE != mfx_res) return mfx_res;
                    bFoundPps = true;
                }
                while (isSEI(startCode.type))
                {
                    mfxBitstream sei = {};
                    MFX_ZERO_MEMORY(sei);
                    sei.Data = (mfxU8*)data - startCode.size;
                    sei.DataLength = size + startCode.size;
                    startCode = ReadStartCode(&data, &size);
                    if (-1 != startCode.type)
                        sei.DataLength -= size + startCode.size;
                    MFX_DEBUG_TRACE_STREAM("Found SEI size " << sei.DataLength);
                    m_uSpsppssei_size += sei.DataLength;
                    mfx_res = SaveSEI(&sei);
                    bFound_sei = true;
                }
                if (isIDR(startCode.type))
                {
                    MFX_DEBUG_TRACE_MSG("Found IDR");
                    bFoundIDR = true;
                    break;
                }
                if (isRegularSlice(startCode.type))
                {
                    MFX_DEBUG_TRACE_MSG("Found regular slice");
                    bFoundRegularSlice = true;
                    break;
                }
                if (-1 == startCode.type) break;
            }
        }
    }

    // cached header to process
    uint32_t CachedHeader_size = 0;
    uint8_t* CachedHeader_data = nullptr;
    if (m_bstBuf->Data && m_bstBuf->DataLength) {
        CachedHeader_data = m_bstBuf->Data + m_bstBuf->DataOffset;
        CachedHeader_size = m_bstBuf->DataLength;
    }
    MFX_DEBUG_TRACE_I32(m_bstBuf->DataLength);
    MFX_DEBUG_TRACE_I32(CachedHeader_size);
    MFX_DEBUG_TRACE_I32(m_uSpsppssei_size);

    // alloc enough space for m_bstEnc->Data
    if (m_bstEnc->MaxLength < m_hucBuffer->sample_size + m_bstBuf->DataLength)
    {
        m_bstEnc->Data = (mfxU8*)realloc(m_bstEnc->Data, m_hucBuffer->sample_size + m_bstBuf->DataLength);
        if (!m_bstEnc->Data)
            return MFX_ERR_MEMORY_ALLOC;
        m_bstEnc->MaxLength = m_hucBuffer->sample_size + m_bstBuf->DataLength;
    }

    packet_info* packet = reinterpret_cast<packet_info*>(baseAddress + sizeof(HUCVideoBuffer) - 8);

    // copy data to m_bstEnc->Data
    m_bstEnc->DataOffset = 0;
    if (CachedHeader_data != nullptr) {
        MFX_DEBUG_TRACE_MSG("copy cached header");
        std::copy(CachedHeader_data, CachedHeader_data + CachedHeader_size, m_bstEnc->Data);
        m_bstEnc->DataLength = CachedHeader_size;
        std::copy(bs, bs + m_hucBuffer->sample_size, m_bstEnc->Data + CachedHeader_size);
        m_bstEnc->DataLength += m_hucBuffer->sample_size;
    } else {
        std::copy(bs, bs + m_hucBuffer->sample_size, m_bstEnc->Data);
        m_bstEnc->DataLength = m_hucBuffer->sample_size;
    }
    m_bstBuf->DataLength = 0;

    // m_bstEnc->EncryptedData->Data points to encrypted part
    if (bFoundIDR || bFoundRegularSlice) {
        mfxEncryptedData *pEncryptedData = new mfxEncryptedData;
        if (pEncryptedData)
        {
            pEncryptedData->Data = m_bstEnc->Data + CachedHeader_size + packet->clear_bytes;
            pEncryptedData->DataLength = packet->encrypted_bytes;
            pEncryptedData->DataOffset = 0;
            pEncryptedData->Next = NULL;
        }
        m_bstEnc->EncryptedData = pEncryptedData;
    }
    m_bstEnc->TimeStamp = pts;
    
    MFX_DEBUG_TRACE_P(m_bstEnc->Data);
    MFX_DEBUG_TRACE_P(m_bstEnc->EncryptedData->Data);

    return mfx_res;
}

IMfxC2FrameConstructor::StartCode MfxC2AVCSecureFrameConstructor::ReadStartCode(const mfxU8** position, mfxU32* size_left)
{
    MFX_DEBUG_TRACE_FUNC;

    return MfxC2AVCFrameConstructor::ReadStartCode(position, size_left);
}

std::shared_ptr<mfxBitstream> MfxC2AVCSecureFrameConstructor::GetMfxBitstream()
{
    MFX_DEBUG_TRACE_FUNC;

    auto pBitstream = MfxC2FrameConstructor::GetMfxBitstream();

    if (m_hucBuffer)
    {
        MFX_ZERO_MEMORY(m_decryptParams);
        m_decryptParams.Header.BufferId = MFX_EXTBUFF_ENCRYPTION_PARAM;
        m_decryptParams.Header.BufferSz = sizeof(mfxExtEncryptionParam);
        m_decryptParams.session = m_hucBuffer->session_id;
        m_decryptParams.uiNumSegments = m_hucBuffer->num_packet_data;
        if (m_hucBuffer->cipher_mode == OEMCrypto_CipherMode_CTR) {
            m_decryptParams.encryption_type = VA_ENCRYPTION_TYPE_SUBSAMPLE_CTR;
        } else {
            m_decryptParams.encryption_type = VA_ENCRYPTION_TYPE_SUBSAMPLE_CBC;
        }
        std::memcpy(m_decryptParams.key_blob, m_hucBuffer->hw_key_data, sizeof(m_hucBuffer->hw_key_data));

        m_decryptParams.pSegmentInfo = (EncryptionSegmentInfo*)malloc(m_hucBuffer->num_packet_data * sizeof(EncryptionSegmentInfo));
        char* baseAddress = reinterpret_cast<char*>(m_hucBuffer);
        for (int i = 0; i < m_hucBuffer->num_packet_data; i++)
        {
            packet_info* packet = reinterpret_cast<packet_info*>(baseAddress + sizeof(HUCVideoBuffer) - 8 + (i * sizeof(packet_info)));
            m_decryptParams.pSegmentInfo[i].segment_start_offset = packet->block_offset;
            m_decryptParams.pSegmentInfo[i].segment_length = m_hucBuffer->sample_size - m_uSpsppssei_size - 4;
            m_decryptParams.pSegmentInfo[i].init_byte_length = packet->clear_bytes + packet->block_offset - m_uSpsppssei_size - 4;
            m_decryptParams.pSegmentInfo[i].partial_aes_block_size = 0;

            IV temp_iv = packet->current_iv;
            std::memcpy(m_decryptParams.pSegmentInfo[i].aes_cbc_iv_or_ctr, temp_iv.data(), temp_iv.size());
            std::memset(m_decryptParams.pSegmentInfo[i].aes_cbc_iv_or_ctr + temp_iv.size(), 0, sizeof(m_decryptParams.pSegmentInfo[i].aes_cbc_iv_or_ctr) - temp_iv.size());
        }

        m_extBufs.clear();
        m_extBufs.push_back(reinterpret_cast<mfxExtBuffer*>(&m_decryptParams));
        m_bstEnc->ExtParam = &m_extBufs.back();
        
        m_bstEnc->NumExtParam = 1;
        m_bstEnc->DataFlag |= MFX_BITSTREAM_COMPLETE_FRAME;

        MFX_DEBUG_TRACE_I32(m_decryptParams.session);
        MFX_DEBUG_TRACE_I32(m_bstEnc->TimeStamp);
        MFX_DEBUG_TRACE_I32(m_bstEnc->DataLength);
        MFX_DEBUG_TRACE_I32(m_bstEnc->EncryptedData->DataLength);

        return m_bstEnc;
    }

    MFX_DEBUG_TRACE_P(pBitstream.get());
    return pBitstream;
}

MfxC2HEVCSecureFrameConstructor::MfxC2HEVCSecureFrameConstructor():
                                MfxC2AVCSecureFrameConstructor()
{
    MFX_DEBUG_TRACE_FUNC;
}

MfxC2HEVCSecureFrameConstructor::~MfxC2HEVCSecureFrameConstructor()
{
    MFX_DEBUG_TRACE_FUNC;
}

