#ifndef _MY_SPAN_H_
#define _MY_SPAN_H_

template <typename _Ty>
struct MySpan
{
    _Ty* m_data;
    size_t m_size;

    MySpan(_Ty* _data, size_t _size)
        : m_data(_data), m_size(_size) {}

    size_t size() {
        return m_size;
    }

    _Ty* data() {
        return m_data;
    }
};

#endif // _MY_SPAN_H_