# pairwise-reset-token-entropy

## 领域

安全

## 主题

重置令牌强度

## 说明

CSPRNG、短时效与单次使用。

初始状态下 `security/reset_token_entropy.py` 中所有函数抛出 `NotImplementedError`，测试全部失败。
修复实现后运行：

```bash
python -m pytest -q
```

期望全部通过。
