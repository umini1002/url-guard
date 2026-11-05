const $ = id => document.getElementById(id);
const apiBase = (globalThis.URL_GUARD_CONFIG?.apiBase || '').replace(/\/+$/, '');
const states = {
  LOW: ['낮음', '탐지된 위험도가 낮아요', '입력한 주소와 출처를 한 번 더 확인해 주세요.'],
  MEDIUM: ['주의', '확인이 필요한 주소예요', '개인정보 입력을 보류하고 아래 탐지 이유를 확인하세요.'],
  HIGH: ['높음', '피싱 위험이 높은 주소예요', '접속과 개인정보 입력을 피하고 대응 방법을 확인하세요.'],
};
let sampleTrigger = null;
let sampleRequest = 0;
let busy = false;
const sampleButtons = () => document.querySelectorAll('[data-sample]');
function setBusy(value) {
  busy=value;
  $('loading').hidden=!value;
  $('submit').disabled=value;
  $('form').setAttribute('aria-busy',String(value));
  sampleButtons().forEach(button=>{button.disabled=value;});
}

function renderReport(data, sample=false) {
  if(!states[data.risk_level] || !Number.isFinite(data.risk_score) || data.risk_score<0 || data.risk_score>100 || !Array.isArray(data.reason) || typeof data.attack_type!=='string' || typeof data.recommendation!=='string')
    throw new Error('결과를 불러오지 못했어요. 잠시 후 다시 시도해 주세요.');
  const [badge,title,advice]=states[data.risk_level];
  $('result').className='panel result';
  $('sample-notice').hidden=!sample; $('close-sample').hidden=!sample;
  $('badge').textContent=badge; $('title').textContent=title; $('advice').textContent=advice;
  $('score').textContent=data.risk_score; $('fill').style.width=data.risk_score+'%';
  $('time').textContent=data.analyzed_at?new Date(data.analyzed_at).toLocaleString('ko-KR'):'';
  $('analyzed-url').textContent=data.url;
  $('reasons').replaceChildren();
  for(const reason of data.reason.length?data.reason:['현재 주소 규칙에서 추가 주의 항목이 발견되지 않았습니다. 낮은 위험도도 안전을 보장하지 않습니다.']) {
    const item=document.createElement('li'); item.textContent=reason; $('reasons').append(item);
  }
  $('attack-type').textContent=data.attack_type;
  $('recommendation').textContent=data.recommendation;
  $('url-characteristics').hidden=!data.features; $('url-characteristics').open=false;
  $('features').replaceChildren();
  if(data.features) {
    for(const [key,label] of [['url_length','주소 길이'],['keyword_count','관련 키워드'],['dot_count','도메인의 점 개수'],['has_ip','IP 주소 사용'],['subdomain_count','하위 도메인 수']]) {
      const box=document.createElement('div');box.className='feature';
      const name=document.createElement('span');name.textContent=label;
      const value=document.createElement('strong');value.textContent=key==='has_ip'?(data.features[key]?'예':'아니오'):data.features[key];
      box.append(name,value);$('features').append(box);
    }
  }
  $('keywords').textContent='확인된 키워드: '+(data.matched_keywords?.join(', ')||'없음');
  $('result').hidden=false;
  $('result').scrollIntoView({behavior:'smooth',block:'start'});
}

$('form').onsubmit=async event=>{
  event.preventDefault();if(busy)return;
  sampleRequest++;$('error').hidden=true;$('result').hidden=true;setBusy(true);
  try {
    const response=await fetch(apiBase + '/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:$('url').value.trim()}),signal:AbortSignal.timeout(90000)});
    if(!(response.headers.get('content-type')||'').includes('application/json'))throw new Error('지금은 검사를 진행할 수 없어요. 잠시 후 다시 시도해 주세요.');
    const data=await response.json();
    if(!response.ok)throw new Error(response.status===422?'올바른 http 또는 https 웹 주소를 입력해 주세요.':'검사를 완료하지 못했어요. 잠시 후 다시 시도해 주세요.');
    renderReport(data);
  } catch(error) {
    $('error').textContent=error.name==='TimeoutError'?'검사 시간이 초과되었어요. 잠시 후 다시 시도해 주세요.':error instanceof TypeError?'일시적으로 검사를 진행할 수 없어요. 잠시 후 다시 시도해 주세요.':error.message;
    $('error').hidden=false;
  } finally {setBusy(false);}
};

$('close-sample').onclick=()=>{$('result').hidden=true;sampleTrigger?.focus();};
let sampleData;
sampleButtons().forEach(button=>{
  button.onclick=async()=>{
    if(busy)return;
    const request=++sampleRequest;sampleTrigger=button;$('error').hidden=true;
    try {
      if(!sampleData) {
        const response=await fetch('samples.json');
        if(!response.ok)throw new Error('샘플을 불러오지 못했어요. 다시 시도해 주세요.');
        sampleData=await response.json();
      }
      if(request!==sampleRequest)return;
      renderReport({...sampleData[button.dataset.sample],analyzed_at:new Date().toISOString()},true);
    } catch(error) {if(request!==sampleRequest)return;$('error').textContent='샘플을 불러오지 못했어요. 다시 시도해 주세요.';$('error').hidden=false;}
  };
});
