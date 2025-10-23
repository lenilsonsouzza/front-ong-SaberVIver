// Efeito na navbar ao scroll
document.addEventListener('DOMContentLoaded', function() {
    const navbar = document.querySelector('.navbar');
    
    function handleScroll() {
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    }
    
    handleScroll();
    window.addEventListener('scroll', handleScroll);
});

// Clique na logo para voltar ao início
document.querySelector('.logo img').addEventListener('click', function(e) {
    e.preventDefault();
    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
});

// Função para copiar PIX
function copiarChavePixSimples() {
    const chave = "centrosaberviver@hotmail.com";
    navigator.clipboard.writeText(chave).then(() => {
        const btn = document.querySelector('.btn-copiar-simples');
        btn.textContent = '✅ Chave Copiada!';
        btn.classList.add('copiado');
        
        setTimeout(() => {
            btn.textContent = '📋 Copiar Chave PIX';
            btn.classList.remove('copiado');
        }, 2000);
    });
}

// Menu Mobile Simples
document.addEventListener('DOMContentLoaded', function() {
    const menuToggle = document.getElementById('menuToggle');
    const navMenu = document.querySelector('.nav-menu');
    
    if (menuToggle && navMenu) {
        menuToggle.addEventListener('click', function() {
            navMenu.classList.toggle('active');
            menuToggle.classList.toggle('active');
        });
        
        // Fechar menu ao clicar nos links
        document.querySelectorAll('.nav-link, .nav-btn').forEach(link => {
            link.addEventListener('click', function() {
                navMenu.classList.remove('active');
                menuToggle.classList.remove('active');
            });
        });
    }
});