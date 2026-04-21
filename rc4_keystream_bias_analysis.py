import matplotlib.pyplot as plt
import numpy as np

# --- RC4実装 (簡略化) ---


def get_keystream_bytes(key_bytes, n_bytes):
    """
    指定された鍵から、最初のn_bytes分の鍵ストリームを生成して返す
    """
    # KRS
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key_bytes[i % len(key_bytes)]) % 256
        state[i], state[j] = state[j], state[i]

    # PRGA
    i = 0
    j = 0
    keystream = []
    for _ in range(n_bytes):
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        t = (state[i] + state[j]) % 256
        keystream.append(state[t])
    return keystream


# --- 実験セクション ---


def run_experiment(iterations=1000000):
    print(f"{iterations}回のシミュレーションを開始します...")

    # 第1, 2, 3バイトの値を記録するリスト (0-255)
    first_byte_counts = np.zeros(256)
    second_byte_counts = np.zeros(256)
    third_byte_counts = np.zeros(256)

    for _ in range(iterations):
        # 毎回異なる鍵を使う必要がある（WEPの脆弱性再現）
        # 現実の攻撃に近い形にするため、最初の3バイトをランダム(IV)にし、
        # その後に固定のパスワードを繋げる
        random_iv = np.random.randint(0, 256, size=3).tolist()
        fixed_key = [ord(c) for c in "SecretKey"]
        full_key = random_iv + fixed_key

        # 最初の3バイトを生成
        stream = get_keystream_bytes(full_key, 3)
        # 各バイトをカウント
        first_byte_counts[stream[0]] += 1
        second_byte_counts[stream[1]] += 1
        third_byte_counts[stream[2]] += 1

    return first_byte_counts, second_byte_counts, third_byte_counts


# 100万回実行
first_counts, second_counts, third_counts = run_experiment(1000000)

# --- 可視化 (ヒストグラム/棒グラフ) ---

fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(12, 12))

theoretical_avg = 1000000 / 256

# 1バイト目の分布グラフ
ax1.bar(range(256), first_counts, color="steelblue", alpha=0.8)
ax1.axhline(
    y=theoretical_avg,
    color="red",
    linestyle="--",
    label="Theoretical Uniform Distribution",
)
ax1.set_title("RC4 Key Stream Bias (1st Byte Analysis)", fontsize=12, fontweight="bold")
ax1.set_xlabel("Byte Value (0-255)")
ax1.set_ylabel("Frequency")
ax1.legend(loc='lower right')
ax1.grid(axis="y", alpha=0.3)

# 2バイト目の分布グラフ
ax2.bar(range(256), second_counts, color="green", alpha=0.8)
ax2.axhline(
    y=theoretical_avg,
    color="red",
    linestyle="--",
    label="Theoretical Uniform Distribution",
)
ax2.set_title("RC4 Key Stream Bias (2nd Byte Analysis)", fontsize=12, fontweight="bold")
ax2.set_xlabel("Byte Value (0-255)")
ax2.set_ylabel("Frequency")
ax2.legend()
ax2.grid(axis="y", alpha=0.3)

# 3バイト目の分布グラフ
ax3.bar(range(256), third_counts, color="orange", alpha=0.8)
ax3.axhline(
    y=theoretical_avg,
    color="red",
    linestyle="--",
    label="Theoretical Uniform Distribution",
)
ax3.set_title("RC4 Key Stream Bias (3rd Byte Analysis)", fontsize=12, fontweight="bold")
ax3.set_xlabel("Byte Value (0-255)")
ax3.set_ylabel("Frequency")
ax3.legend()
ax3.grid(axis="y", alpha=0.3)

plt.tight_layout()
plt.show()

# 統計的なズレを表示
print("\n--- 統計分析結果 ---")
print(f"\n【第1バイト】")
print(f"値 '0' の出現回数: {int(first_counts[0])} (期待値: {theoretical_avg:.1f})")
print(f"値 '2' の出現回数: {int(first_counts[2])} (期待値: {theoretical_avg:.1f})")

print(f"\n【第2バイト】")
print(f"値 '0' の出現回数: {int(second_counts[0])} (期待値: {theoretical_avg:.1f})")
print(f"値 '2' の出現回数: {int(second_counts[2])} (期待値: {theoretical_avg:.1f})")

print(f"\n【第3バイト】")
print(f"値 '0' の出現回数: {int(third_counts[0])} (期待値: {theoretical_avg:.1f})")
print(f"値 '2' の出現回数: {int(third_counts[2])} (期待値: {theoretical_avg:.1f})")
