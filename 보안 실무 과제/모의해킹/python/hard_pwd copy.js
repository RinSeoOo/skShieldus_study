HTTP/1.1 200 
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
Last-Modified: Wed, 18 Jun 2025 16:54:48 GMT
Accept-Ranges: bytes
Content-Type: application/javascript
Content-Length: 7770
Date: Tue, 29 Jul 2025 05:37:15 GMT
Keep-Alive: timeout=20
Connection: keep-alive

$('#pw').keyboard({type:'default'});

$(document).ready(function() {
	alert('로그인 전 반드시 EQST Sign 프로그램을 실행시켜주세요!');
	$(".loading").css({
		"visibility" : "visible"
	});
	var comdata={"cmd":"check"};
	$.ajax({
		type:"POST",
		url:"http://localhost:14060/eqstsign/api",
		dataType: "text",
		contentType : 'text/plain; charset=utf-8',
		data: JSON.stringify(comdata),
		error: function(){
			$(".loading").css({
				"visibility" : "hidden"
			});
			alert('공동 인증서가 설치되지 않았습니다.\n설치 페이지로 이동합니다.');
			window.location.href = "/auth/pkimenu/installpki";
		},
		success: function(data){
			var obj = JSON.parse(data);
			if(obj.result == "ok"){
				$.ajax({
	               type:"POST",
	               url:"/sign/checksecuritysolution",
	               dataType:"text",
	               data: {"solutionmsg" : obj.message},
	               error: function(){
	                  alert('공동 인증서가 설치되지 않았습니다.\n설치 페이지로 이동합니다.');
					  window.location.href = "/auth/pkimenu/installpki";
	               },
	               success: function(data){
	                  var obj1 = JSON.parse(data);
	                  if(obj1.result=="Y"){
	                     $(".loading").css({
							"visibility" : "hidden"
						});
	                  }
	                  else{
	                     alert('공동 인증서가 설치되지 않았습니다.\n설치 페이지로 이동합니다.');
					     window.location.href = "/auth/pkimenu/installpki";
	                  }
	               }
	            });
			}
		}
	});
   $('#pw').on('focus', function(){
      if($('#pw').val().length>20){
         $('#pw').val($('#pw').val().substr(0, 20));
      }
   });
});

$(document).ready(function(){
   $("#id").keydown(function(key){
      if(key.keyCode == 13){
         $("#pw").focus();
      }      
   });
   $("#pw").keydown(function(key){
      if(key.keyCode == 13){
         var id = $('#id').val();
         var pw = $('#pw').val();
         var regid = /^[A-Za-z0-9+]{6,15}$/;
         var regpw = /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,20}$/;
         if(!id || !pw){
            alert("로그인 정보를 모두 입력해주세요!");
         }else if(false === regid.test(id)){
            alert("ID는 영어 대소문자, 숫자를 포함하여 6~15자리만 가능합니다.");
         }else if(false === regpw.test(pw)){
            alert("비밀번호는 8자 이상이어야 하며, 영어 대소문자/숫자/특수문자를 모두 포함해야 합니다.");
         }
         else{
            var e2e_data = encrypt(id+":"+pw);
            $(".loading").css({
               "visibility" : "visible"
            });
            $.ajax({
               type:"POST",
               url:"/sign/dologin",
               dataType:"text",
               data: {"e2e_data" : e2e_data},
               error: function(){
                  alert('다시 시도해 주세요!');
                  window.location = "/sign/loginmenu";
               },
               success: function(data){
                  var obj = JSON.parse(data);
                  if(obj.result=="Y"){
                     window.location = obj.url;
                  }
                  else{
                     alert("로그인 정보가 올바르지 않습니다.");
                     window.location = "/sign/loginmenu";
                  }
               }
            });
         }
      }      
   });
});

$('#loginbtn').click(function(){
   var id = $('#id').val();
   var pw = $('#pw').val();
   var regid = /^[A-Za-z0-9+]{6,15}$/;
   var regpw = /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,20}$/;
   if(!id || !pw){
      alert("로그인 정보를 모두 입력해주세요!");
   }else if(false === regid.test(id)){
      alert("ID는 영어 대소문자, 숫자를 포함하여 6~15자리만 가능합니다.");
   }else if(false === regpw.test(pw)){
      alert("비밀번호는 8자 이상이어야 하며, 영어 대소문자/숫자/특수문자를 모두 포함해야 합니다.");
   }
   else{
      var e2e_date = encrypt(id+":"+pw);
      
      $(".loading").css({
         "visibility" : "visible"
      });
      $.ajax({
         type:"POST",
         url:"/sign/dologin",
         dataType:"text",
         data: {"e2e_data" : e2e_date},
         error: function(){
            alert('다시 시도해 주세요!');
            window.location = "/sign/loginmenu";
         },
         success: function(data){
            var obj = JSON.parse(data);
            if(obj.result=="Y"){
               window.location = obj.url;
            }
            else{
               alert("로그인 정보가 올바르지 않습니다.");
               window.location = "/sign/loginmenu";
            }
         }
      });
   }   
});

$('#signup').click(function(){
   location.href="/sign/signupagreement";
});

$('#pkilogin').click(function(){
	$(".loading").css({
		"visibility" : "visible"
	});
	var comdata={"cmd":"check"};
	$.ajax({
		type:"POST",
		url:"http://localhost:14060/eqstsign/api",
		dataType: "text",
		contentType : 'text/plain; charset=utf-8',
		data: JSON.stringify(comdata),
		error: function(){
			$(".loading").css({
				"visibility" : "hidden"
			});
			alert('공동 인증서가 설치되지 않았습니다.\n설치 페이지로 이동합니다.');
			window.location.href = "/auth/pkimenu/installpki";
		},
		success: function(data){
			$.ajax({
		      type:"GET",
		      url:"/sign/pkilogin",
		      dataType:"text",
		      error: function(){
		         alert('다시 시도해 주세요!');
		         	$(".loading").css({
						"visibility" : "hidden"
					});
		      },
		      success: function(data){
		         var obj = JSON.parse(data);
		         var comdata={"cmd":"login", "token":obj.code};
		         $.ajax({
		            type:"POST",
		            url:"http://localhost:14060/eqstsign/api",
		            dataType: "text",
		            contentType : 'text/plain; charset=utf-8',
		            data: JSON.stringify(comdata),
		            error: function(){
		               alert('다시 시도해 주세요!');
		               	$(".loading").css({
							"visibility" : "hidden"
						});
		            },
		            success: function(data1){
		               var obj1 = JSON.parse(data1);
		               if(obj1.result == "ok"){
		                  var e2e_data = encrypt(obj1.encryptdata+":");
		                  $.ajax({
		                     type:"POST",
		                     url:"/sign/pkidologin",
		                     dataType: "text",
		                     data: {"e2e_data" : e2e_data},
		                     error: function(){
		                        alert('다시 시도해 주세요!');
		                        	$(".loading").css({
										"visibility" : "hidden"
									});
		                     },
		                     success: function(data2){
		                        var obj2 = JSON.parse(data2);
		                        if(obj2.result=="Y"){
		                           window.location = obj2.url;
		                        }
		                        else{
		                           alert("로그인 정보가 올바르지 않습니다.");
		                           	$(".loading").css({
										"visibility" : "hidden"
									});
		                        }
		                     }
		                  });
		               }
		               else{
		                  alert("로그인에 실패했습니다.");
		                  	$(".loading").css({
								"visibility" : "hidden"
							});
		               }
		            }
		         });
		      }
		   });
		}
	});
});