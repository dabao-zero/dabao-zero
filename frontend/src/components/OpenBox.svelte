<script lang="ts">
  interface Props {
    food?: boolean;
    sticker?: string | null;
    steam?: boolean;
    label?: string;
    maxWidth?: number;
  }
  let {
    food = true,
    sticker = "packed fresh",
    steam = true,
    label = food
      ? "An open styrofoam takeaway box packed with chicken rice, cucumber and chilli, tied with a green rubber band, with chopsticks beside it"
      : "An empty open styrofoam takeaway box tied with a green rubber band",
    maxWidth = 440,
  }: Props = $props();
</script>

<svg
  viewBox="0 0 320 240"
  fill="none"
  stroke-linecap="round"
  stroke-linejoin="round"
  role="img"
  aria-label={label}
  style="width: 100%; max-width: {maxWidth}px; display: block; margin: 0 auto;"
>
  <ellipse cx="166" cy="222" rx="124" ry="10" fill="var(--md-sys-color-on-surface)" opacity=".10" />
  {#if food}
    <path class="box-chop" d="M52 232 L286 206" stroke-width="4" />
    <path class="box-chop" d="M58 238 L292 212" stroke-width="4" />
  {/if}
  <path class="box-lid box-ink" d="M60 40 C58 22 70 12 90 10 L236 4 C254 3 264 12 264 28 L262 80 C262 90 254 96 242 96 L92 102 C74 103 64 96 62 84 Z" stroke-width="3" />
  <path class="box-panel box-ink" d="M76 38 C76 30 82 26 92 25 L234 20 C244 20 249 25 249 33 L247 70 C247 76 242 80 234 80 L96 86 C84 86 78 82 77 74 Z" stroke-width="2.5" />
  {#if sticker}
    <g transform="rotate(-3 160 54)">
      <rect x="112" y="40" width="96" height="30" rx="4" class="box-lid box-ink" stroke-width="2" />
      <text x="160" y="62" text-anchor="middle" font-size="19" font-weight="700" style="font-family: var(--dabao-hand);" fill="var(--dabao-box-ink)" stroke="none">{sticker}</text>
    </g>
  {/if}
  <path class="box-tray box-ink" d="M44 150 L66 196 C70 204 78 208 88 207 L246 196 C256 195 264 190 267 182 L290 134 Z" stroke-width="3" />
  <path class="box-lid box-ink" d="M38 130 C36 112 56 104 98 100 L226 96 C266 95 290 106 292 122 L290 140 C288 156 270 164 246 166 L84 176 C58 178 40 170 38 150 Z" stroke-width="3" />
  <path class="box-tray box-ink" d="M58 128 C58 118 76 112 104 110 L222 107 C250 106 268 114 269 124 L268 140 C267 150 252 156 232 157 L90 165 C70 166 58 160 58 150 Z" stroke-width="2.5" />
  {#if food}
    <g class="box-ink" stroke-width="2.2">
      <path class="f-chicken" d="M168 120 C178 112 204 112 214 118 C218 126 208 132 190 133 C176 133 166 128 168 120 Z" />
      <path class="f-chicken" d="M196 116 C208 108 236 110 246 118 C250 127 238 134 218 135 C204 135 194 125 196 116 Z" />
      <path class="f-rice" d="M78 140 C74 118 96 104 122 106 C148 102 170 116 168 138 C164 150 90 156 78 140 Z" />
      <path d="M96 124 l5 3 M112 117 l5 3 M130 119 l5 3 M146 128 l5 3 M104 138 l5 3 M124 134 l5 3" stroke-width="1.6" opacity=".55" />
      <circle class="f-cuc" cx="206" cy="146" r="9" /><circle class="f-cuc-in" cx="206" cy="146" r="5.5" stroke-width="1.2" />
      <circle class="f-cuc" cx="228" cy="143" r="9" /><circle class="f-cuc-in" cx="228" cy="143" r="5.5" stroke-width="1.2" />
      <path class="f-chilli" d="M172 146 C176 140 188 140 190 146 C190 152 176 153 172 146 Z" stroke-width="1.8" />
    </g>
  {/if}
  <path class="box-band" d="M40 160 C70 186 210 190 290 142" stroke-width="7" />
  {#if steam && food}
    <g class="box-steam">
      <path d="M118 100c-8-8 8-14 0-24" /><path d="M156 96c-8-8 8-14 0-24" /><path d="M194 100c-8-8 8-14 0-24" />
    </g>
  {/if}
</svg>
